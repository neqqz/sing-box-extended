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
	"syscall"
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

func (s *h2Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientConn == nil {
		return false
	}
	if s.dead {
		return true
	}
	state := s.clientConn.State()
	return state.Closed || state.Closing
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

func (c *Client) setQUICConn(conn *quic.Conn) {
	c.quicConnMu.Lock()
	c.quicConn = conn
	c.quicConnMu.Unlock()
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
	conn.closeFn = sync.OnceFunc(func() { c.count.Add(-1) })
	ctx, cancel := context.WithCancel(c.ctx)
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
	if isNetworkUnreachable(err) {
		// Интерфейс, к которому привязан весь пул (auto_detect_interface),
		// на момент дозвона ещё не поднял маршрут (типичный "моргнувший"
		// хендовер вышки/включение мобильных данных). Остальные клиенты в
		// пуле почти наверняка привязаны к тому же мёртвому интерфейсу и
		// провалятся так же — сбрасываем пул целиком сразу, вместо того
		// чтобы дать десяткам параллельных запросов повиснуть каждому на
		// собственные до 30с (DefaultSessionTimeout) до истечения их
		// родительского контекста.
		_ = c.Close()
	} else {
		c.removeClient(primary)
	}
	fresh, freshErr := c.forceNewClient()
	if freshErr != nil {
		return nil, err
	}
	return fresh.Dial(ctx, host)
}

// isNetworkUnreachable распознаёт ENETUNREACH/EHOSTUNREACH — признак того,
// что проблема не в конкретном соединении, а в самом сетевом интерфейсе,
// к которому мы сейчас привязаны.
func isNetworkUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
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
	if isNetworkUnreachable(err) {
		_ = c.Close()
	} else {
		c.removeClient(primary)
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
	
	// Фильтруем мертвые сессии
	live := c.clients[:0]
	for _, t := range c.clients {
		if t.IsClosed() {
			_ = t.Close()
			continue
		}
		live = append(live, t)
	}
	c.clients = live
	
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
