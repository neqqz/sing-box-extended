//go:build with_utls

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/transport/trusttunnel/obfs"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"golang.org/x/net/http2"
)

type ClientOptions struct {
	Dialer                  N.Dialer
	TLSConfig               tls.Config
	Server                  M.Socksaddr
	Username                string
	Password                string
	QUIC                    bool
	DisablePathMTUDiscovery bool
	CongestionControl       string
	CWND                    int
	HealthCheck             bool
	MaxConnections          int
	MinStreams              int
	MaxStreams              int
	UDPPaddingMin           int
	UDPPaddingMax           int
	JitterMinMS             int
	JitterMaxMS             int
	JitterPackets           int
}

type Client struct {
	ctx              context.Context
	cancel           context.CancelFunc
	server           M.Socksaddr
	serverString     string
	username         string
	password         string
	roundTripper     http.RoundTripper
	quicDialer       func(ctx context.Context) (*quic.Conn, io.Closer, error)
	quicConn         *quic.Conn
	quicCloser       io.Closer
	h3ClientConn     *http3.ClientConn
	h3Transport      *http3.Transport
	quicMtx          sync.Mutex
	isQUIC           bool
	startOnce        sync.Once
	healthCheck      bool
	healthCheckTimer atomic.Pointer[time.Timer]
	count            atomic.Int64
	udpPaddingMin    int
	udpPaddingMax    int
}

type quicRoundTripper struct {
	client *Client
}

func (q *quicRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	h3, err := q.client.getQUICClientConn(req.Context())
	if err != nil {
		return nil, err
	}
	return h3.RoundTrip(req)
}

func (c *Client) getQUICClientConn(ctx context.Context) (*http3.ClientConn, error) {
	c.quicMtx.Lock()
	defer c.quicMtx.Unlock()
	if c.ctx.Err() != nil {
		return nil, c.ctx.Err()
	}
	if c.h3ClientConn != nil && c.quicConn != nil && c.quicConn.Context().Err() == nil {
		return c.h3ClientConn, nil
	}
	if c.h3ClientConn != nil {
		_ = c.h3ClientConn.CloseWithError(0, "")
		c.h3ClientConn = nil
	}
	if c.quicConn != nil {
		_ = c.quicConn.CloseWithError(0, "")
		c.quicConn = nil
	}
	if c.quicCloser != nil {
		_ = c.quicCloser.Close()
		c.quicCloser = nil
	}

	conn, closer, err := c.quicDialer(ctx)
	if err != nil {
		return nil, err
	}
	h3Conn := c.h3Transport.NewClientConn(conn)
	c.quicConn = conn
	c.quicCloser = closer
	c.h3ClientConn = h3Conn

	go func() {
		<-conn.Context().Done()
		c.quicMtx.Lock()
		if c.quicConn == conn {
			_ = closer.Close()
			c.h3ClientConn = nil
			c.quicConn = nil
			c.quicCloser = nil
		}
		c.quicMtx.Unlock()
		if isFatalTransportError(conn.Context().Err()) {
			c.cancel()
		}
	}()

	return h3Conn, nil
}

func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		ctx:           ctx,
		cancel:        cancel,
		server:        options.Server,
		serverString:  options.Server.String(),
		username:      options.Username,
		password:      options.Password,
		healthCheck:   options.HealthCheck,
		udpPaddingMin: options.UDPPaddingMin,
		udpPaddingMax: options.UDPPaddingMax,
		isQUIC:        options.QUIC,
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
		quicConfig := &quic.Config{
			MaxIdleTimeout:          DefaultSessionTimeout * 2,
			KeepAlivePeriod:         DefaultKeepAlivePeriod,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
			EnableDatagrams:         true,
		}
		client.quicDialer = func(dialCtx context.Context) (*quic.Conn, io.Closer, error) {
			udpConn, err := options.Dialer.DialContext(dialCtx, N.NetworkUDP, client.server)
			if err != nil {
				return nil, nil, err
			}
			var conn *quic.Conn
			if qd, ok := options.TLSConfig.(tls.QUICDialer); ok {
				pktConn := obfs.NewJitterPacketConn(bufio.NewUnbindPacketConn(udpConn), options.JitterMinMS, options.JitterMaxMS, options.JitterPackets)
				conn, err = qd.DialEarly(dialCtx, pktConn, udpConn.RemoteAddr(), quicConfig)
			} else {
				jConn := obfs.NewJitterConn(udpConn, options.JitterMinMS, options.JitterMaxMS, options.JitterPackets)
				conn, err = qtls.DialEarly(dialCtx, jConn, options.TLSConfig, quicConfig)
			}
			if err != nil {
				_ = udpConn.Close()
				return nil, nil, err
			}
			conn.SetCongestionControl(congestionControlFactory(conn))
			return conn, udpConn, nil
		}
		client.h3Transport = &http3.Transport{
			EnableDatagrams: true,
			QUICConfig:      quicConfig,
		}
		client.roundTripper = &quicRoundTripper{client: client}
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
		}
	}
	return client, nil
}

func (c *Client) start() {
	if c.healthCheck {
		timer := time.NewTimer(DefaultHealthCheckTimeout)
		c.healthCheckTimer.Store(timer)
		go c.loopHealthCheck(timer)
	}
}

func (c *Client) loopHealthCheck(timer *time.Timer) {
	for {
		select {
		case <-timer.C:
		case <-c.ctx.Done():
			timer.Stop()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		err := c.HealthCheck(ctx)
		cancel()
		if err != nil {
			_ = c.Close()
			return
		}
	}
}

func (c *Client) resetHealthCheckTimer() {
	if timer := c.healthCheckTimer.Load(); timer != nil {
		timer.Reset(DefaultHealthCheckTimeout)
	}
}

func (c *Client) roundTrip(ctx context.Context, request *http.Request, conn *httpConn) error {
	c.startOnce.Do(c.start)
	pipeReader, pipeWriter := io.Pipe()
	request.Body = pipeReader
	remoteAddr := conn.remoteAddr
	localAddr := conn.localAddr
	*conn = httpConn{writer: pipeWriter, created: make(chan struct{}), remoteAddr: remoteAddr, localAddr: localAddr}
	c.count.Add(1)
	conn.closeFn = sync.OnceFunc(func() { c.count.Add(-1) })
	requestCtx, cancel := context.WithCancel(c.ctx)
	conn.cancelFn = cancel
	go func() {
		request = request.WithContext(requestCtx)
		response, err := c.roundTripper.RoundTrip(request)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setup(nil, err)
			if isFatalTransportError(err) {
				c.cancel()
			}
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
	select {
	case <-ctx.Done():
		_ = conn.Close()
		return ctx.Err()
	case <-conn.created:
		if conn.createErr != nil {
			_ = conn.Close()
			return conn.createErr
		}
		return nil
	}
}

func isFatalTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var streamErr http2.StreamError
	if errors.As(err, &streamErr) {
		return false
	}
	var quicStreamErr *quic.StreamError
	if errors.As(err, &quicStreamErr) {
		return false
	}
	return true
}

func (c *Client) newConnectRequest(host string) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: c.serverString},
		Header: http.Header{
			"Proxy-Authorization": {buildTokenAuth(c.username, c.password, host)},
		},
		Host: host,
	}
}

func (c *Client) Dial(ctx context.Context, host string) (net.Conn, error) {
	conn := &tcpConn{
		httpConn: httpConn{
			remoteAddr: parseRemoteAddr(host),
		},
	}
	err := c.roundTrip(ctx, c.newConnectRequest(host), &conn.httpConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.isQUIC {
		h3, err := c.getQUICClientConn(ctx)
		if err != nil {
			return nil, err
		}
		str, err := h3.OpenRequestStream(ctx)
		if err != nil {
			return nil, err
		}
		req := c.newConnectRequest(UDPMagicAddress).WithContext(ctx)
		err = str.SendRequestHeader(req)
		if err != nil {
			_ = str.Close()
			return nil, err
		}
		rsp, err := str.ReadResponse()
		if err != nil {
			_ = str.Close()
			return nil, err
		}
		if rsp.StatusCode != http.StatusOK {
			_ = str.Close()
			return nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
		}
		c.resetHealthCheckTimer()
		pktCtx, pktCancel := context.WithCancel(c.ctx)
		c.count.Add(1)
		conn := &quicPacketConn{
			stream:     str,
			ctx:        pktCtx,
			cancel:     pktCancel,
			remoteAddr: c.server.UDPAddr(),
			paddingMin: c.udpPaddingMin,
			paddingMax: c.udpPaddingMax,
			closeFn:    sync.OnceFunc(func() { c.count.Add(-1) }),
		}
		return conn, nil
	}

	conn := &packetConn{
		httpConn: httpConn{
			remoteAddr: c.server.UDPAddr(),
		},
		paddingMin: c.udpPaddingMin,
		paddingMax: c.udpPaddingMax,
	}
	err := c.roundTrip(ctx, c.newConnectRequest(UDPMagicAddress), &conn.httpConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) Close() error {
	c.cancel()
	c.quicMtx.Lock()
	if c.h3ClientConn != nil {
		_ = c.h3ClientConn.CloseWithError(0, "")
		c.h3ClientConn = nil
	}
	if c.quicConn != nil {
		_ = c.quicConn.CloseWithError(0, "")
		c.quicConn = nil
	}
	if c.quicCloser != nil {
		_ = c.quicCloser.Close()
		c.quicCloser = nil
	}
	if c.h3Transport != nil {
		_ = c.h3Transport.Close()
	}
	c.quicMtx.Unlock()
	if closer, ok := c.roundTripper.(io.Closer); ok {
		_ = closer.Close()
	}
	if t, ok := c.roundTripper.(*http2.Transport); ok {
		t.CloseIdleConnections()
	}
	if timer := c.healthCheckTimer.Swap(nil); timer != nil {
		timer.Stop()
	}
	return nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	req := c.newConnectRequest(HealthCheckMagicAddress).WithContext(ctx)
	response, err := c.roundTripper.RoundTrip(req)
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
	closed         bool
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
	t, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return t.Dial(ctx, host)
}

func (c *MultiplexClient) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	t, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return t.ListenPacket(ctx)
}

func (c *MultiplexClient) Reset() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, t := range c.clients {
		_ = t.Close()
	}
	c.clients = nil
}

func (c *MultiplexClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.closed = true
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
	if c.closed {
		return nil, net.ErrClosed
	}
	n := 0
	var deadClients []*Client
	for _, t := range c.clients {
		if t.ctx.Err() == nil {
			c.clients[n] = t
			n++
		} else {
			deadClients = append(deadClients, t)
		}
	}
	clear(c.clients[n:])
	c.clients = c.clients[:n]
	for _, t := range deadClients {
		_ = t.Close()
	}

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

func (c *MultiplexClient) newClientLocked() (*Client, error) {
	t, err := NewClient(c.ctx, c.options)
	if err != nil {
		return nil, err
	}
	c.clients = append(c.clients, t)
	return t, nil
}
