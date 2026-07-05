package trusttunnel

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"golang.org/x/net/http2"
)

var (
	appName       = "sing-box"
	appVersion    = C.Version
	tcpUserAgent  = runtime.GOOS + " " + appName + "/" + appVersion
	udpUserAgent  = runtime.GOOS + " " + UDPMagicAddress
	icmpUserAgent = runtime.GOOS + " " + ICMPMagicAddress
)

type Dialer interface {
	Dial(ctx context.Context, host string) (net.Conn, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
	Close() error
}

type ClientOptions struct {
	Dialer            N.Dialer
	TLSConfig         tls.Config
	Server            M.Socksaddr
	Username          string
	Password          string
	QUIC              bool
	CongestionControl string
	CWND              int
	Logger            logger.Logger
	HealthCheck       bool
	MaxConnections    int
	MinStreams        int
	MaxStreams        int
}

type Client struct {
	ctx              context.Context
	cancel           context.CancelFunc
	server           M.Socksaddr
	serverString     string
	auth             string
	roundTripper     http.RoundTripper
	startOnce        sync.Once
	healthCheck      bool
	healthCheckTimer *time.Timer
	count            atomic.Int64
}

func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		ctx:          ctx,
		cancel:       cancel,
		server:       options.Server,
		serverString: options.Server.String(),
		auth:         buildAuth(options.Username, options.Password),
		healthCheck:  options.HealthCheck,
	}
	if options.QUIC {
		congestionControlFactory, err := congestion.NewCongestionControl(options.CongestionControl, options.CWND, ntp.TimeFuncFromContext(ctx))
		if err != nil {
			cancel()
			return nil, err
		}
		if len(options.TLSConfig.NextProtos()) == 0 {
			options.TLSConfig.SetNextProtos([]string{"h3"})
		}
		client.roundTripper = &http3.Transport{
			QUICConfig: &quic.Config{
				MaxIdleTimeout:  DefaultSessionTimeout * 2,
				KeepAlivePeriod: DefaultHealthCheckTimeout,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *stdtls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpConn, err := options.Dialer.DialContext(ctx, N.NetworkUDP, client.server)
				if err != nil {
					return nil, err
				}
				pktConn := bufio.NewUnbindPacketConn(udpConn)
				var conn *quic.Conn
				if qd, ok := options.TLSConfig.(tls.QUICDialer); ok {
					conn, err = qd.DialEarly(ctx, pktConn, udpConn.RemoteAddr(), cfg)
				} else {
					conn, err = qtls.DialEarly(ctx, pktConn, udpConn.RemoteAddr(), options.TLSConfig, cfg)
				}
				if err != nil {
					return nil, err
				}
				conn.SetCongestionControl(congestionControlFactory(conn))
				return conn, nil
			},
		}
	} else {
		if len(options.TLSConfig.NextProtos()) == 0 {
			options.TLSConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		tlsDialer := tls.NewDialer(options.Dialer, options.TLSConfig)
		client.roundTripper = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *stdtls.Config) (net.Conn, error) {
				return tlsDialer.DialContext(ctx, network, client.server)
			},
			AllowHTTP: true,
			// Без этого http2.Transport не шлёт PING в простое соединения:
			// на мобильной сети carrier NAT сам рвёт неактивный TCP-маппинг
			// (в отличие от QUIC, где ниже явно задан KeepAlivePeriod), и
			// разрыв обнаруживается только при следующей попытке отправки.
			//
			// ReadIdleTimeout=PingTimeout=DefaultHealthCheckTimeout (7s) был
			// слишком агрессивным: суммарное окно терпимости ~14с — любой
			// скачок RTT на мобильной сети (переключение вышки, кратковре-
			// менный провал) укладывал живое соединение с "client connection
			// lost". ReadIdleTimeout держим прежним (не пинговать реже, чем
			// раз в DefaultHealthCheckTimeout, — этого достаточно для NAT),
			// а PingTimeout увеличиваем — терпимость к задержке ACK на пинг,
			// а не к общей неактивности.
			ReadIdleTimeout: DefaultHealthCheckTimeout,
			PingTimeout:     DefaultSessionTimeout,
		}
	}
	return client, nil
}

func (c *Client) start() {
	if c.healthCheck {
		c.healthCheckTimer = time.NewTimer(DefaultHealthCheckTimeout)
		go c.loopHealthCheck()
	}
}

func (c *Client) loopHealthCheck() {
	for {
		select {
		case <-c.healthCheckTimer.C:
		case <-c.ctx.Done():
			c.healthCheckTimer.Stop()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		_ = c.HealthCheck(ctx)
		cancel()
	}
}

func (c *Client) resetHealthCheckTimer() {
	if c.healthCheckTimer == nil {
		return
	}
	c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
}

func (c *Client) roundTrip(request *http.Request, conn *httpConn) {
	c.startOnce.Do(c.start)
	pipeReader, pipeWriter := io.Pipe()
	request.Body = pipeReader
	*conn = httpConn{writer: pipeWriter, created: make(chan struct{})}
	c.count.Add(1)
	conn.closeFn = sync.OnceFunc(func() { c.count.Add(-1) })
	ctx, cancel := context.WithCancel(c.ctx)
	conn.cancelFn = cancel
	go func() {
		timeout := time.AfterFunc(C.TCPTimeout, cancel)
		defer timeout.Stop()
		request = request.WithContext(ctx)
		response, err := c.roundTripper.RoundTrip(request)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setup(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setup(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setup(response.Body, nil)
		}
	}()
}

func (c *Client) newConnectRequest(host, userAgent string) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: c.serverString},
		Header: http.Header{
			"User-Agent":          {userAgent},
			"Proxy-Authorization": {c.auth},
		},
		Host: host,
	}
}

func (c *Client) Dial(ctx context.Context, host string) (net.Conn, error) {
	conn := &tcpConn{}
	c.roundTrip(c.newConnectRequest(host, tcpUserAgent), &conn.httpConn)
	if err := conn.waitCreated(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn := &clientPacketConn{}
	c.roundTrip(c.newConnectRequest(UDPMagicAddress, udpUserAgent), &conn.httpConn)
	if err := conn.waitCreated(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) Close() error {
	c.cancel()
	if closer, ok := c.roundTripper.(io.Closer); ok {
		_ = closer.Close()
	}
	if t, ok := c.roundTripper.(*http2.Transport); ok {
		t.CloseIdleConnections()
	}
	if c.healthCheckTimer != nil {
		c.healthCheckTimer.Stop()
	}
	return nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	response, err := c.roundTripper.RoundTrip(c.newConnectRequest(HealthCheckMagicAddress, runtime.GOOS).WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}
	return nil
}

// fallbackDelay — сколько ждём ответа от уже существующего соединения,
// прежде чем параллельно попробовать заведомо новое. Пассивное обнаружение
// мёртвого TCP/H2-соединения (ReadIdleTimeout+PingTimeout) может занимать
// десятки секунд — именно это ощущается как "недоступно, потом через время
// доступно" при смене сети (WiFi<->cellular, WiFi<->WiFi). Гонка по образцу
// Happy Eyeballs не отменяет первую попытку (вдруг она жива и просто
// медленная), но не заставляет ждать её полного тайм-аута, если есть шанс,
// что параллельная попытка на свежем соединении отработает быстрее.
const fallbackDelay = 600 * time.Millisecond

type MultiplexClient struct {
	mutex          sync.Mutex
	maxConnections int
	minStreams     int
	maxStreams     int
	ctx            context.Context
	options        ClientOptions
	clients        []*Client
}

func NewMultiplexClient(ctx context.Context, options ClientOptions) (*MultiplexClient, error) {
	maxConnections := options.MaxConnections
	minStreams := options.MinStreams
	maxStreams := options.MaxStreams
	if maxConnections == 0 && minStreams == 0 && maxStreams == 0 {
		maxConnections = 8
		minStreams = 5
	}
	client, err := NewClient(ctx, options)
	if err != nil {
		return nil, err
	}
	return &MultiplexClient{
		maxConnections: maxConnections,
		minStreams:     minStreams,
		maxStreams:     maxStreams,
		ctx:            ctx,
		options:        options,
		clients:        []*Client{client},
	}, nil
}

// raceResult — обёртка результата одной из гонящихся попыток.
type raceResult[T any] struct {
	conn T
	err  error
}

// raceDial запускает primary немедленно и, если тот не ответил за
// fallbackDelay, параллельно запускает fallback на гарантированно новом
// клиенте. Возвращает первый успешный результат; если оба провалились —
// ошибку той попытки, что завершилась последней (обычно информативнее).
func raceDial[T any](
	primary func() (T, error),
	fallback func() (T, error),
) (T, error) {
	results := make(chan raceResult[T], 2)
	go func() {
		conn, err := primary()
		results <- raceResult[T]{conn, err}
	}()

	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()

	select {
	case res := <-results:
		if res.err == nil {
			return res.conn, nil
		}
		// primary уже провалился быстрее fallbackDelay — сразу пробуем
		// свежий клиент синхронно, гонка тут не нужна.
		return fallback()
	case <-timer.C:
	}

	go func() {
		conn, err := fallback()
		results <- raceResult[T]{conn, err}
	}()

	first := <-results
	if first.err == nil {
		return first.conn, nil
	}
	second := <-results
	if second.err == nil {
		return second.conn, nil
	}
	return second.conn, second.err
}

func (c *MultiplexClient) Dial(ctx context.Context, host string) (net.Conn, error) {
	primary, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return raceDial(
		func() (net.Conn, error) {
			conn, dialErr := primary.Dial(ctx, host)
			if dialErr != nil {
				c.removeClient(primary)
			}
			return conn, dialErr
		},
		func() (net.Conn, error) {
			fresh, fErr := c.forceNewClient()
			if fErr != nil {
				return nil, fErr
			}
			return fresh.Dial(ctx, host)
		},
	)
}

func (c *MultiplexClient) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	primary, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return raceDial(
		func() (net.PacketConn, error) {
			conn, dialErr := primary.ListenPacket(ctx)
			if dialErr != nil {
				c.removeClient(primary)
			}
			return conn, dialErr
		},
		func() (net.PacketConn, error) {
			fresh, fErr := c.forceNewClient()
			if fErr != nil {
				return nil, fErr
			}
			return fresh.ListenPacket(ctx)
		},
	)
}

// removeClient убирает t из пула сразу при первой неудаче Dial/ListenPacket
// на нём — не дожидаясь ленивой чистки в newClientLocked. Без этого
// getClient() мог бы выбрать тот же уже известный сломанным транспорт снова
// на следующий вызов (например, если у него count==0 — он выглядит
// "свободным" и приоритетным для повторного использования).
func (c *MultiplexClient) removeClient(dead *Client) {
	c.mutex.Lock()
	for i, t := range c.clients {
		if t == dead {
			c.clients = append(c.clients[:i], c.clients[i+1:]...)
			break
		}
	}
	c.mutex.Unlock()
	_ = dead.Close()
}

func (c *MultiplexClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var errs []error
	for _, t := range c.clients {
		if err := t.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.clients = nil
	return errors.Join(errs...)
}

func (c *MultiplexClient) getClient() (*Client, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var transport *Client
	for _, t := range c.clients {
		if transport == nil || t.count.Load() < transport.count.Load() {
			transport = t
		}
	}
	if transport == nil {
		return c.newClientLocked()
	}
	numStreams := int(transport.count.Load())
	if numStreams == 0 {
		return transport, nil
	}
	if c.maxConnections > 0 {
		if len(c.clients) >= c.maxConnections || numStreams < c.minStreams {
			return transport, nil
		}
	} else if c.maxStreams > 0 && numStreams < c.maxStreams {
		return transport, nil
	}
	return c.newClientLocked()
}

// forceNewClient гарантированно создаёт новый *Client, минуя выбор из пула
// (в отличие от getClient, который мог бы снова вернуть только что умерший
// транспорт).
func (c *MultiplexClient) forceNewClient() (*Client, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.newClientLocked()
}

func (c *MultiplexClient) newClientLocked() (*Client, error) {
	// Без этого список клиентов только растёт: при переключении сети
	// (WiFi<->cellular) старые *Client становятся простаивающими (count==0),
	// но никогда не закрываются и не убираются из пула — копятся навечно,
	// каждый со своим health-check таймером и открытым (или уже мёртвым)
	// TCP/TLS-соединением. Оставляем максимум один простаивающий про запас,
	// остальные простаивающие закрываем перед добавлением нового.
	c.clients = pruneIdleClients(c.clients)
	t, err := NewClient(c.ctx, c.options)
	if err != nil {
		return nil, err
	}
	c.clients = append(c.clients, t)
	return t, nil
}

// pruneIdleClients оставляет не более одного простаивающего (count==0)
// клиента, закрывая остальные, и возвращает обновлённый список.
func pruneIdleClients(clients []*Client) []*Client {
	kept := make([]*Client, 0, len(clients))
	idleKept := false
	for _, t := range clients {
		if t.count.Load() > 0 || !idleKept {
			kept = append(kept, t)
			if t.count.Load() == 0 {
				idleKept = true
			}
			continue
		}
		_ = t.Close()
	}
	return kept
}
