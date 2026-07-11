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
	UDPPaddingMin     int
	UDPPaddingMax     int
}

type Client struct {
	ctx              context.Context
	cancel           context.CancelFunc
	server           M.Socksaddr
	serverString     string
	auth             string
	roundTripper     http.RoundTripper
	session          *h2Session 
	quicConnMu       sync.RWMutex
	quicConn         *quic.Conn 
	startOnce        sync.Once
	healthCheck      bool
	healthCheckTimer *time.Timer
	count            atomic.Int64
	udpPaddingMin    int
	udpPaddingMax    int
}

type h2Session struct {
	transport *http2.Transport
	server    M.Socksaddr
	tlsDialer tls.Dialer

	mu         sync.Mutex
	clientConn *http2.ClientConn
	dead       bool
	dialMu     sync.Mutex 
}

func (s *h2Session) GetClientConn(req *http.Request, _ string) (*http2.ClientConn, error) {
	s.mu.Lock()
	if s.clientConn != nil && !s.dead {
		state := s.clientConn.State()
		if !state.Closed && !state.Closing {
			cc := s.clientConn
			s.mu.Unlock()
			return cc, nil
		}
	}
	s.mu.Unlock()

	s.dialMu.Lock()
	defer s.dialMu.Unlock()

	s.mu.Lock()
	if s.clientConn != nil && !s.dead {
		state := s.clientConn.State()
		if !state.Closed && !state.Closing {
			cc := s.clientConn
			s.mu.Unlock()
			return cc, nil
		}
	}
	s.mu.Unlock()

	conn, err := s.tlsDialer.DialContext(req.Context(), N.NetworkTCP, s.server)
	if err != nil {
		return nil, err
	}
	clientConn, err := s.transport.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	s.mu.Lock()
	s.clientConn = clientConn
	s.dead = false
	s.mu.Unlock()

	return clientConn, nil
}

func (s *h2Session) MarkDead(conn *http2.ClientConn) {
	s.mu.Lock()
	if conn == s.clientConn {
		s.dead = true
	}
	s.mu.Unlock()
}

// status возвращает (hardClosed, draining) для текущего clientConn.
// hardClosed — соединение реально мертво (transport.MarkDead его отбраковал,
// либо http2 сообщает state.Closed): активные стримы на нём уже ни на что
// не годны, их контекст можно смело отменять.
// draining — получен GOAWAY, http2.ClientConn в state.Closing: НЕ новых
// стримов, но уже открытые стримы по спецификации HTTP/2 должны доиграть
// до конца. Это не то же самое, что "мертво".
func (s *h2Session) status() (hardClosed, draining bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientConn == nil {
		return false, false
	}
	if s.dead {
		return true, false
	}
	state := s.clientConn.State()
	return state.Closed, state.Closing
}

func (s *h2Session) isClosed() bool {
	hardClosed, draining := s.status()
	return hardClosed || draining
}

func (s *h2Session) isHardClosed() bool {
	hardClosed, _ := s.status()
	return hardClosed
}

func (s *h2Session) isDraining() bool {
	_, draining := s.status()
	return draining
}

func (c *Client) IsClosed() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
	}
	if c.session != nil {
		return c.session.isClosed()
	}
	c.quicConnMu.RLock()
	conn := c.quicConn
	c.quicConnMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
			return true
		default:
		}
	}
	return false
}

// IsHardClosed reports whether the underlying connection is genuinely dead
// (unusable even for streams already in flight), as opposed to merely
// draining after a graceful GOAWAY. Only hard-dead clients should have their
// context canceled — canceling a draining client's context kills every
// active multiplexed stream on it even though HTTP/2 promises those streams
// may run to completion.
func (c *Client) IsHardClosed() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
	}
	if c.session != nil {
		return c.session.isHardClosed()
	}
	c.quicConnMu.RLock()
	conn := c.quicConn
	c.quicConnMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
			return true
		default:
		}
	}
	return false
}

// IsDraining reports whether the client is in a graceful GOAWAY drain: no
// new streams should be routed to it, but existing streams are left alone.
func (c *Client) IsDraining() bool {
	if c.session != nil {
		return c.session.isDraining()
	}
	return false
}

func (c *Client) setQUICConn(conn *quic.Conn) {
	c.quicConnMu.Lock()
	c.quicConn = conn
	c.quicConnMu.Unlock()
}

// EverConnected reports whether this Client ever managed to establish a
// working underlying connection (h2 ClientConn / QUIC conn) at least once,
// as opposed to having failed on its very first dial. Used by
// MultiplexClient to decide whether a retry-on-fresh-client is worth the
// extra full timeout: if we never connected even once, the server/network
// path itself is almost certainly the problem, and dialing yet another fresh
// client at the same destination over the same broken path will just burn a
// second full C.TCPTimeout for an identical failure.
func (c *Client) EverConnected() bool {
	if c.session != nil {
		c.session.mu.Lock()
		defer c.session.mu.Unlock()
		return c.session.clientConn != nil
	}
	c.quicConnMu.RLock()
	defer c.quicConnMu.RUnlock()
	return c.quicConn != nil
}

func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		ctx:           ctx,
		cancel:        cancel,
		server:        options.Server,
		serverString:  options.Server.String(),
		auth:          buildAuth(options.Username, options.Password),
		healthCheck:   options.HealthCheck,
		udpPaddingMin: options.UDPPaddingMin,
		udpPaddingMax: options.UDPPaddingMax,
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
				// Оптимизировано для мобильных: не дергаем сеть слишком часто
				MaxIdleTimeout:  time.Minute * 2,
				KeepAlivePeriod: time.Second * 30, 
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
				client.setQUICConn(conn)
				return conn, nil
			},
		}
	} else {
		if len(options.TLSConfig.NextProtos()) == 0 {
			options.TLSConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		transport := &http2.Transport{
			AllowHTTP:       true,
			// Включаем мягкий low-level пинг на уровне HTTP/2 стека
			ReadIdleTimeout: time.Second * 45,
			PingTimeout:     time.Second * 15,
		}
		session := &h2Session{
			transport: transport,
			server:    client.server,
			tlsDialer: tls.NewDialer(options.Dialer, options.TLSConfig),
		}
		transport.ConnPool = session
		client.roundTripper = transport
		client.session = session
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
	consecutiveFailures := 0
	for {
		select {
		case <-c.healthCheckTimer.C:
		case <-c.ctx.Done():
			c.healthCheckTimer.Stop()
			return
		}
		if c.count.Load() > 0 {
			// На клиенте прямо сейчас есть живые стримы — это само по себе
			// доказательство того, что соединение работает. Не гоняем
			// отдельный CONNECT health-check, который на загруженном
			// H2-соединении может ложно упереться в очередь за тем же
			// потоком и словить фантомный таймаут, хотя данные реально идут.
			consecutiveFailures = 0
			c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
			continue
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		err := c.HealthCheck(ctx)
		cancel()
		if err != nil {
			consecutiveFailures++
			// Защита батареи: если первый чек упал, ждем 15 секунд вместо жесткого спама раз в 2 секунды
			if consecutiveFailures < 2 {
				c.healthCheckTimer.Reset(15 * time.Second)
				continue
			}
			_ = c.Close()
			return
		}
		consecutiveFailures = 0
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
	conn.closeFn = sync.OnceFunc(func() {
		if c.count.Add(-1) == 0 {
			// Клиент уже помечен мёртвым (health-check/getClient), но пока
			// на нём были активные стримы, мы намеренно не рвали соединение
			// (см. комментарий у cancel ниже). Как только последний стрим
			// реально завершился — дожимаем: закрываем опустевшую
			// TCP-сессию, иначе она повиснет открытой до серверного таймаута.
			select {
			case <-c.ctx.Done():
				if closer, ok := c.roundTripper.(io.Closer); ok {
					_ = closer.Close()
				}
				if t, ok := c.roundTripper.(*http2.Transport); ok {
					t.CloseIdleConnections()
				}
			default:
			}
		}
	})
	// ВАЖНО: контекст запроса намеренно НЕ наследуется от c.ctx.
	// Раньше было ctx, cancel := context.WithCancel(c.ctx) — из-за этого
	// c.cancel() (вызывается из c.Close(), в т.ч. из loopHealthCheck при
	// двух неудачных health-check'ах подряд) мгновенно отменял контексты
	// ВСЕХ активных мультиплексированных стримов на этом h2-соединении
	// разом, даже полностью живых, которые просто не успели ответить на
	// собственный health-check из-за конкуренции за то же H2-соединение.
	// Именно это выглядело как "отваливающийся http2": пачка не связанных
	// между собой стримов к разным хостам падала с context canceled в один
	// и тот же момент. Теперь у запроса свой независимый контекст с
	// единственным источником отмены — вызывающая сторона (conn.Close())
	// и жёсткий таймаут ниже. Смерть/переиспользование Client'а на уровне
	// пула по-прежнему решается через IsHardClosed()/getClient() и влияет
	// только на маршрутизацию НОВЫХ стримов, а не на уже открытые.
	ctx, cancel := context.WithCancel(context.Background())
	conn.cancelFn = cancel
	go func() {
		hardTimeout := time.AfterFunc(C.TCPTimeout, cancel)
		defer hardTimeout.Stop()
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
	conn := &clientPacketConn{paddingMin: c.udpPaddingMin, paddingMax: c.udpPaddingMax}
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

func (c *MultiplexClient) Dial(ctx context.Context, host string) (net.Conn, error) {
	primary, err := c.getClient()
	if err != nil {
		return nil, err
	}
	conn, err := primary.Dial(ctx, host)
	if err == nil {
		return conn, nil
	}
	// ВАЖНО: раньше isNetworkUnreachable(err) (ENETUNREACH/EHOSTUNREACH —
	// типичный "моргнувший" хендовер вышки/включение мобильных данных на
	// клиенте с auto_detect_interface) сбрасывал ВЕСЬ пул (c.Close()),
	// отменяя контекст каждого Client'а в пуле и тем самым разом обрывая
	// все туннели, которые в этот момент активно передавали данные через
	// другие, полностью исправные соединения пула. Один неудачный дозвон
	// нового стрима не означает, что уже установленные соединения тоже
	// мертвы — их убьёт (и корректно вычистит) getClient()/health-check
	// сам, если интерфейс действительно лёг. Поэтому здесь трогаем только
	// тот единственный клиент, на котором произошёл сбой.
	everConnected := primary.EverConnected()
	c.removeClient(primary)
	if !everConnected {
		// primary ни разу не смог даже установить соединение (первый же
		// дозвон до сервера сдох по таймауту/сети) — сервер или путь до
		// него сейчас попросту недоступны. Ретраить на СВЕЖЕМ клиенте к
		// ТОЙ ЖЕ дестинации по той же дохлой сети — это гарантированно
		// ещё один полный C.TCPTimeout ради идентичного результата
		// (именно так 15s превращались в наблюдаемые 30s на каждый
		// стрим). Отдаём ошибку сразу — вызывающая сторона (роутер,
		// urltest-селектор, сам клиент-приложение) отреагирует быстрее.
		return nil, err
	}
	fresh, freshErr := c.forceNewClient()
	if freshErr != nil {
		return nil, err
	}
	return fresh.Dial(ctx, host)
}

func (c *MultiplexClient) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	primary, err := c.getClient()
	if err != nil {
		return nil, err
	}
	conn, err := primary.ListenPacket(ctx)
	if err == nil {
		return conn, nil
	}
	// See the comment in Dial: never nuke the whole pool over a single
	// failed dial — only the client that actually failed is affected, and
	// we skip the fresh-client retry entirely if this client never had a
	// working connection to begin with (see EverConnected).
	everConnected := primary.EverConnected()
	c.removeClient(primary)
	if !everConnected {
		return nil, err
	}
	fresh, freshErr := c.forceNewClient()
	if freshErr != nil {
		return nil, err
	}
	return fresh.ListenPacket(ctx)
}

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

	// Вычищаем только по-настоящему мёртвые сессии (IsHardClosed). Сессию в
	// состоянии graceful GOAWAY-дрейна (IsDraining, но не hard-closed) не
	// трогаем и не отменяем её контекст здесь — на ней могут быть активные
	// мультиплексированные стримы, которым HTTP/2 обещал доиграть до конца;
	// раньше это место било IsClosed() (Closed || Closing) и убивало такую
	// сессию целиком при любом обычном GOAWAY/idle-таймауте сервера, разом
	// обрывая все её активные туннели — именно это и выглядело как "вечно
	// отваливающийся" http2-транспорт.
	live := c.clients[:0]
	for _, t := range c.clients {
		if t.IsHardClosed() {
			_ = t.Close()
			continue
		}
		live = append(live, t)
	}
	c.clients = live

	var transport *Client
	for _, t := range c.clients {
		if t.IsDraining() {
			// Дренящаяся сессия не годится для НОВЫХ стримов, но остаётся
			// в пуле нетронутой, пока не станет hard-closed или не опустеет
			// (тогда её приберёт pruneIdleClients/следующий проход выше).
			continue
		}
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

func (c *MultiplexClient) forceNewClient() (*Client, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.newClientLocked()
}

func (c *MultiplexClient) newClientLocked() (*Client, error) {
	c.clients = pruneIdleClients(c.clients)
	t, err := NewClient(c.ctx, c.options)
	if err != nil {
		return nil, err
	}
	c.clients = append(c.clients, t)
	return t, nil
}

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
