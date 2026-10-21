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
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/transport/trusttunnel/obfs"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"golang.org/x/net/http2"
)

var (
	tcpUserAgent = runtime.GOOS + " sing-box/" + C.Version
	udpUserAgent = runtime.GOOS + " " + UDPMagicAddress
)

type Dialer interface {
	Dial(ctx context.Context, host string) (net.Conn, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
	Close() error
}

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
	Logger                  logger.Logger
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
	ctx           context.Context
	cancel        context.CancelFunc
	server        M.Socksaddr
	serverString  string
	auth          string
	roundTripper  http.RoundTripper
	count         atomic.Int64
	udpPaddingMin int
	udpPaddingMax int
}

func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		ctx:           ctx,
		cancel:        cancel,
		server:        options.Server,
		serverString:  options.Server.String(),
		auth:          buildAuth(options.Username, options.Password),
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
		quicConfig := &quic.Config{
			MaxIdleTimeout:          DefaultSessionTimeout * 2,
			KeepAlivePeriod:         DefaultKeepAlivePeriod,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		}
		client.roundTripper = &http3.Transport{
			QUICConfig: quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *stdtls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpConn, err := options.Dialer.DialContext(ctx, N.NetworkUDP, client.server)
				if err != nil {
					return nil, err
				}
				var conn *quic.Conn
				if qd, ok := options.TLSConfig.(tls.QUICDialer); ok {
					pktConn := obfs.NewJitterPacketConn(bufio.NewUnbindPacketConn(udpConn), options.JitterMinMS, options.JitterMaxMS, options.JitterPackets)
					conn, err = qd.DialEarly(ctx, pktConn, udpConn.RemoteAddr(), cfg)
				} else {
					conn, err = qtls.DialEarly(ctx, udpConn, options.TLSConfig, cfg)
				}
				if err != nil {
					_ = udpConn.Close()
					return nil, err
				}
				conn.SetCongestionControl(congestionControlFactory(conn))
				// quic.Dial* never closes a PacketConn it did not create, so the socket
				// would leak for every connection that ends (idle, network change).
				go func() {
					<-conn.Context().Done()
					_ = udpConn.Close()
				}()
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
		}
	}
	return client, nil
}

func (c *Client) roundTrip(ctx context.Context, request *http.Request, conn *httpConn) error {
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
	conn := &tcpConn{
		httpConn: httpConn{
			remoteAddr: parseRemoteAddr(host),
		},
	}
	err := c.roundTrip(ctx, c.newConnectRequest(host, tcpUserAgent), &conn.httpConn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn := &clientPacketConn{
		httpConn: httpConn{
			remoteAddr: c.server.UDPAddr(),
		},
		paddingMin: c.udpPaddingMin,
		paddingMax: c.udpPaddingMax,
	}
	err := c.roundTrip(ctx, c.newConnectRequest(UDPMagicAddress, udpUserAgent), &conn.httpConn)
	if err != nil {
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
