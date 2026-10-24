package trusttunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing-box/transport/trusttunnel/obfs"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	"golang.org/x/net/http2"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TrustTunnelInboundOptions](registry, C.TypeTrustTunnel, NewInbound)
}

func createFallbackHandler(server string) http.Handler {
	if server == "" {
		return nil
	}
	target := server
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.Out.Host = u.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.NotFound(w, r)
		},
	}
}

// checkSNI возвращает true, если sni разрешён (или проверка выключена).
func checkSNI(allowed []string, sni string) bool {
	if len(allowed) == 0 {
		return true
	}
	return common.Contains(allowed, sni)
}

// sniMiddleware отклоняет запросы, SNI которых не входит в allowedSNI.
// Используется только для QUIC/H3 — там r.TLS заполняет сам quic-go/http3,
// надёжно. Для TCP SNI проверяется раньше, в serveConn (см. ниже).
type sniMiddleware struct {
	next            http.Handler
	fallbackHandler http.Handler
	allowedSNI      []string
	logger          logger.ContextLogger
}

func newSNIMiddleware(next http.Handler, fallback http.Handler, allowed []string, log logger.ContextLogger) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	return &sniMiddleware{next: next, fallbackHandler: fallback, allowedSNI: allowed, logger: log}
}

func (m *sniMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	if !checkSNI(m.allowedSNI, sni) {
		m.logger.Debug("trusttunnel: rejected SNI: ", sni)
		if m.fallbackHandler != nil {
			m.fallbackHandler.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	m.next.ServeHTTP(w, r)
}

type Inbound struct {
	inbound.Adapter
	ctx            context.Context
	router         adapter.Router
	logger         logger.ContextLogger
	options        option.TrustTunnelInboundOptions
	listener       *listener.Listener
	service        *trusttunnel.Service
	fallbackHandler http.Handler
	h2Server       *http2.Server
	http3Server    *http3.Server
	httpTLSConfig  tls.ServerConfig
	http3TLSConfig tls.ServerConfig
	network        []string
	// randomReloader: текущий набор проверок ClientHello.Random — статичные
	// client_random_prefix ИЛИ секреты ротации client_random_prefix_secret
	// (соединение принимается, если подходит под ЛЮБУЮ запись). Набор
	// подменяется на лету при изменении файлов (см. Start/Close и
	// common/tls/random_prefix_reload.go); nil, если проверка выключена.
	// Один и тот же набор читают TCP/h2-путь (PrefixListener) и QUIC-путь
	// (ServerClientRandomVerify).
	randomReloader  *tls.RandomPrefixReloader
	randomCancel    context.CancelFunc
	randomPrefixLen int
	// conns — принятые TCP-соединения, прошедшие prefix-check: Close обязан их
	// закрыть, иначе h2Server.ServeConn (блокируется на всю жизнь соединения)
	// и записи в ResponseWriter переживают остановку inbound.
	connsMtx     sync.Mutex
	conns        map[net.Conn]struct{}
	connsClosed  bool
	quicListener io.Closer
}

const tlsHandshakeTimeout = 20 * time.Second

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	randomSource := tls.RandomPrefixSource{
		Prefixes:   options.ClientRandomPrefix,
		Secrets:    options.ClientRandomPrefixSecret,
		PrefixFile: options.ClientRandomPrefixFile,
		SecretFile: options.ClientRandomPrefixSecretFile,
	}
	var randomReloader *tls.RandomPrefixReloader
	if randomSource.Enabled() {
		var err error
		randomReloader, err = tls.NewRandomPrefixReloader(randomSource)
		if err != nil {
			return nil, err
		}
	}
	if err := validateUDPPadding(options.UDPPadding); err != nil {
		return nil, err
	}
	networkList := options.Network.Build()
	if len(networkList) == 0 {
		networkList = []string{N.NetworkTCP}
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTrustTunnel, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		options: options,
		network: networkList,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		randomReloader:  randomReloader,
		randomPrefixLen: options.ClientRandomPrefixLen,
	}
	udpPaddingMin, udpPaddingMax := paddingRange(options.UDPPadding)
	fallbackHandler := createFallbackHandler(options.FallbackServer)
	h.fallbackHandler = fallbackHandler
	service := trusttunnel.NewService(trusttunnel.ServiceOptions{
		Ctx:             ctx,
		Logger:          logger,
		Handler:         (*inboundHandler)(h),
		FallbackHandler: fallbackHandler,
		UDPPaddingMin:   udpPaddingMin,
		UDPPaddingMax:   udpPaddingMax,
		TimeFunc:        ntp.TimeFuncFromContext(ctx),
	})
	userMap := make(map[string]string, len(options.Users))
	for _, u := range options.Users {
		userMap[u.Name] = u.Password
	}
	service.UpdateUsers(userMap)
	h.service = service
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.connsMtx.Lock()
	h.connsClosed = false
	h.conns = make(map[net.Conn]struct{})
	h.connsMtx.Unlock()
	scope.Add(h.Close)

	// Горячая замена client_random_prefix / client_random_prefix_secret из файлов.
	if h.randomReloader != nil {
		reloadCtx, cancel := context.WithCancel(h.ctx)
		h.randomCancel = cancel
		go h.randomReloader.Run(reloadCtx, 0, h.logger)
	}

	// Для TCP SNI проверяется вручную в serveConn (см. ниже) — там надёжный
	// источник данных (tlsConn.ConnectionState()), в отличие от r.TLS в
	// net/http. sniMiddleware держим только для QUIC/H3: там r.TLS заполняет
	// сам quic-go/http3, и это надёжно.
	h3Handler := newSNIMiddleware(h.service, h.fallbackHandler, h.options.AllowedSNI, h.logger)

	// ── TCP / HTTP2 ────────────────────────────────────────────────────
	if common.Contains(h.network, N.NetworkTCP) {
		var err error
		h.httpTLSConfig, err = tls.NewServer(h.ctx, h.logger, common.PtrValueOrDefault(h.options.TLS))
		if err != nil {
			return err
		}
		if len(h.httpTLSConfig.NextProtos()) == 0 {
			h.httpTLSConfig.SetNextProtos([]string{http2.NextProtoTLS})
		} else if !common.Contains(h.httpTLSConfig.NextProtos(), http2.NextProtoTLS) {
			h.httpTLSConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, h.httpTLSConfig.NextProtos()...))
		}

		rawListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		// TCP: pre-TLS peek, проверяем bytes[11:43] ClientHello.Random до хендшейка.
		var randomProvider tls.RandomPrefixProvider
		if h.randomReloader != nil {
			randomProvider = h.randomReloader
		}
		prefixChecker := obfs.NewPrefixChecker(rawListener.Addr(), randomProvider, h.options.ClientRandomPrefixLen, h.options.FallbackServer, int(h.options.FallbackSNIPort), h.logger)
		if err = h.httpTLSConfig.Start(); err != nil {
			return err
		}

		h.h2Server = &http2.Server{
			IdleTimeout:                  20 * time.Second,
			MaxUploadBufferPerStream:     8 << 20,  // 8 MB
			MaxUploadBufferPerConnection: 16 << 20, // 16 MB
		}
		go h.acceptLoop(rawListener, prefixChecker, h.service)
	}

	// ── UDP / HTTP3 (QUIC) ─────────────────────────────────────────────
	if common.Contains(h.network, N.NetworkUDP) {
		var err error
		h.http3TLSConfig, err = tls.NewServer(h.ctx, h.logger, common.PtrValueOrDefault(h.options.TLS))
		if err != nil {
			return err
		}
		if err = qtls.ConfigureHTTP3(h.http3TLSConfig); err != nil {
			return err
		}
		if err = h.http3TLSConfig.Start(); err != nil {
			return err
		}
		scope.Add(h.http3TLSConfig.Close)
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		congestionControlFactory, err := congestion.NewCongestionControl(
			h.options.CongestionController, h.options.CWND, ntp.TimeFuncFromContext(h.ctx),
		)
		if err != nil {
			return err
		}
		h.http3Server = &http3.Server{
			Handler:         h3Handler,
			EnableDatagrams: true,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestionControlFactory(conn))
				return ctx
			},
		}
		quicConfig := &quic.Config{
			MaxIdleTimeout:          trusttunnel.DefaultSessionTimeout * 2,
			KeepAlivePeriod:         trusttunnel.DefaultKeepAlivePeriod,
			MaxIncomingStreams:      4096,
			Allow0RTT:               true,
			DisablePathMTUDiscovery: h.options.DisablePathMTUDiscovery,
			EnableDatagrams:         true,
		}
		if h.randomReloader != nil {
			reloader := h.randomReloader
			length := tls.RandomPrefixLenOrDefault(h.randomPrefixLen)
			replay := tls.NewReplayCache()
			quicConfig.ServerClientRandomVerify = func(random [32]byte, clientHello []byte) bool {
				set := reloader.Current()
				if len(set.Secrets) > 0 {
					bind, ok := obfs.ExtractKeyShareFromHandshakeMessage(clientHello)
					if !ok {
						return false
					}
					return tls.MatchRotatingRandomPrefixBound(set.Secrets, length, random[:], bind) && !replay.Seen(random[:])
				}
				return tls.MatchAnyRandomPrefix(set.Prefixes, random[:]) && !replay.Seen(random[:])
			}
		}
		timingMin, timingMax, timingPackets := timingRange(h.options.Timing)
		jitteredUDPConn := obfs.NewJitterPacketConn(udpConn, timingMin, timingMax, timingPackets)
		quicListener, err := qtls.ListenEarly(jitteredUDPConn, h.http3TLSConfig, quicConfig)
		if err != nil {
			return err
		}
		h.quicListener = quicListener
		scope.Add(quicListener.Close)
		go func() {
			_ = h.http3Server.ServeListener(quicListener)
			_ = udpConn.Close()
		}()
	}

	return nil
}

// trackConn регистрирует соединение; false — inbound уже закрыт (соединение
// закрыто здесь же).
func (h *Inbound) trackConn(conn net.Conn) bool {
	h.connsMtx.Lock()
	defer h.connsMtx.Unlock()
	if h.connsClosed {
		_ = conn.Close()
		return false
	}
	if h.conns == nil {
		h.conns = make(map[net.Conn]struct{})
	}
	h.conns[conn] = struct{}{}
	return true
}

func (h *Inbound) untrackConn(conn net.Conn) {
	h.connsMtx.Lock()
	delete(h.conns, conn)
	h.connsMtx.Unlock()
}

func (h *Inbound) Close() error {
	if h.randomCancel != nil {
		h.randomCancel()
	}
	h.connsMtx.Lock()
	h.connsClosed = true
	conns := h.conns
	h.conns = nil
	h.connsMtx.Unlock()
	for conn := range conns {
		_ = conn.Close()
	}
	return common.Close(
		h.listener,
		h.quicListener,
		common.PtrOrNil(h.service),
		common.PtrOrNil(h.http3Server),
		h.httpTLSConfig,
		h.http3TLSConfig,
	)
}

func (h *Inbound) acceptLoop(rawListener net.Listener, checker *obfs.PrefixChecker, handler http.Handler) {
	var delay time.Duration
	timingMin, timingMax, timingPackets := timingRange(h.options.Timing)
	for {
		rawConn, err := rawListener.Accept()
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && (netErr.Temporary() || netErr.Timeout()) { //nolint:staticcheck
				delay = min(max(delay*2, 5*time.Millisecond), time.Second)
				h.logger.Warn("trusttunnel: accept: ", err, "; retrying in ", delay)
				select {
				case <-time.After(delay):
					continue
				case <-h.ctx.Done():
					return
				}
			}
			h.logger.Error("trusttunnel: accept: ", err)
			return
		}
		delay = 0
		trusttunnel.SetTCPCongestionControl(rawConn, h.options.CongestionController)
		go func() {
			conn := rawConn
			if checker != nil {
				var ok bool
				if conn, ok = checker.Check(rawConn); !ok {
					return
				}
			}
			jc := obfs.NewJitterConn(conn, timingMin, timingMax, timingPackets)
			if !h.trackConn(jc) {
				return
			}
			defer h.untrackConn(jc)
			h.serveConn(jc, handler)
		}()
	}
}

func (h *Inbound) serveConn(rawConn net.Conn, handler http.Handler) {
	ctx, cancel := context.WithTimeout(h.ctx, tlsHandshakeTimeout)
	defer cancel()
	tlsConn, err := tls.ServerHandshake(ctx, rawConn, h.httpTLSConfig)
	if err != nil {
		h.logger.Debug("trusttunnel: TLS handshake failed: ", err)
		rawConn.Close()
		return
	}
	if !checkSNI(h.options.AllowedSNI, tlsConn.ConnectionState().ServerName) {
		sni := tlsConn.ConnectionState().ServerName
		h.logger.Debug("trusttunnel: rejected SNI: ", sni)
		tlsConn.Close()
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		tlsConn.Close()
		return
	}
	h.h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
		Context: h.ctx,
		Handler: handler,
	})
}
func (h *Inbound) UpdateUsers(users []option.TrustTunnelUser) {
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		userMap[u.Name] = u.Password
	}
	h.service.UpdateUsers(userMap)
}

func (h *Inbound) Options() option.TrustTunnelInboundOptions {
	return h.options
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	ctx = log.ContextWithNewID(ctx)
	var inboundCtx adapter.InboundContext
	inboundCtx.Inbound = h.Tag()
	inboundCtx.InboundType = h.Type()
	//nolint:staticcheck
	inboundCtx.InboundDetour = h.listener.ListenOptions().Detour
	inboundCtx.Source = metadata.Source
	inboundCtx.Destination = metadata.Destination
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		inboundCtx.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", inboundCtx.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", inboundCtx.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, inboundCtx, nil)
	return nil
}

func (h *inboundHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	ctx = log.ContextWithNewID(ctx)
	var inboundCtx adapter.InboundContext
	inboundCtx.Inbound = h.Tag()
	inboundCtx.InboundType = h.Type()
	//nolint:staticcheck
	inboundCtx.InboundDetour = h.listener.ListenOptions().Detour
	inboundCtx.Source = metadata.Source
	inboundCtx.Destination = metadata.Destination
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		inboundCtx.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", inboundCtx.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", inboundCtx.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, inboundCtx, nil)
	return nil
}
