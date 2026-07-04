package trusttunnel

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
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
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TrustTunnelInboundOptions](registry, C.TypeTrustTunnel, NewInbound)
}

// parseRandomPrefix парсит "hex" или "hex/mask_hex" → (prefix, mask, err).
// Возвращает nil, nil, nil если строка пустая.
func parseRandomPrefix(raw string) (prefix, mask []byte, err error) {
	if raw == "" {
		return nil, nil, nil
	}
	parts := strings.SplitN(raw, "/", 2)
	prefix, err = hex.DecodeString(parts[0])
	if err != nil {
		return nil, nil, errors.New("client_random_prefix: invalid hex: " + err.Error())
	}
	if len(prefix) == 0 || len(prefix) > 32 {
		return nil, nil, errors.New("client_random_prefix: must be 1–32 bytes")
	}
	if len(parts) == 2 {
		mask, err = hex.DecodeString(parts[1])
		if err != nil {
			return nil, nil, errors.New("client_random_prefix: invalid mask hex: " + err.Error())
		}
		if len(mask) != len(prefix) {
			return nil, nil, errors.New("client_random_prefix: mask length must equal prefix length")
		}
	} else {
		mask = bytes.Repeat([]byte{0xff}, len(prefix))
	}
	return prefix, mask, nil
}

// sniMiddleware отклоняет запросы, SNI которых не входит в allowedSNI.
// Работает одинаково для H2 (r.TLS.ServerName) и H3 (то же поле).
// Если allowedSNI пуст — пропускает всё.
type sniMiddleware struct {
	next       http.Handler
	allowedSNI map[string]struct{}
	logger     logger.ContextLogger
}

func newSNIMiddleware(next http.Handler, allowed []string, log logger.ContextLogger) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	m := make(map[string]struct{}, len(allowed))
	for _, sni := range allowed {
		m[sni] = struct{}{}
	}
	return &sniMiddleware{next: next, allowedSNI: m, logger: log}
}

func (m *sniMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	if _, ok := m.allowedSNI[sni]; !ok {
		m.logger.Debug("trusttunnel: rejected SNI: ", sni)
		http.Error(w, "Forbidden", http.StatusForbidden)
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
	httpServer     *http.Server
	http3Server    *http3.Server
	httpTLSConfig  tls.ServerConfig
	http3TLSConfig tls.ServerConfig
	network        []string
	randomPrefix   []byte
	randomMask     []byte
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	prefix, mask, err := parseRandomPrefix(options.ClientRandomPrefix)
	if err != nil {
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
		randomPrefix: prefix,
		randomMask:   mask,
	}
	service := trusttunnel.NewService(trusttunnel.ServiceOptions{
		Ctx:     ctx,
		Logger:  logger,
		Handler: (*inboundHandler)(h),
	})
	userMap := make(map[string]string, len(options.Users))
	for _, u := range options.Users {
		userMap[u.Name] = u.Password
	}
	service.UpdateUsers(userMap)
	h.service = service
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	// Оборачиваем сервис в SNI-middleware (no-op если AllowedSNI пуст).
	handler := newSNIMiddleware(h.service, h.options.AllowedSNI, h.logger)

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
		checkedListener, err := trusttunnel.NewPrefixListener(rawListener, h.options.ClientRandomPrefix, h.logger)
		if err != nil {
			return err
		}
		if err = h.httpTLSConfig.Start(); err != nil {
			return err
		}
		tlsListener := aTLS.NewListener(checkedListener, h.httpTLSConfig)

		h.httpServer = &http.Server{
			Handler:           handler,
			BaseContext:       func(net.Listener) context.Context { return h.ctx },
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       trusttunnel.DefaultSessionTimeout*2 + 10*time.Second,
		}
		// ConfigureServer регистрирует HTTP/2 через ALPN-согласование для TLS.
		// h2c.NewHandler здесь НЕПРАВИЛЬНЫЙ выбор — он для cleartext h2c, а не TLS.
		if err = http2.ConfigureServer(h.httpServer, &http2.Server{
			IdleTimeout: trusttunnel.DefaultSessionTimeout * 2,
		}); err != nil {
			return err
		}
		go func() {
			if sErr := h.httpServer.Serve(tlsListener); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				h.logger.Error("trusttunnel H2 server: ", sErr)
			}
		}()
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
			Handler: handler,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestionControlFactory(conn))
				return ctx
			},
		}
		quicListener, err := qtls.ListenEarly(udpConn, h.http3TLSConfig, &quic.Config{
			MaxIdleTimeout:  trusttunnel.DefaultSessionTimeout * 2,
			KeepAlivePeriod: trusttunnel.DefaultHealthCheckTimeout,
			// QUIC: client_random_prefix проверяется в sagernet/quic-go
			// на уровне cryptoSetup.handleMessage (NewCryptoSetupServer).
			ServerClientRandomPrefix: h.randomPrefix,
			ServerClientRandomMask:   h.randomMask,
			MaxIncomingStreams:        1 << 60,
			Allow0RTT:                true,
		})
		if err != nil {
			return err
		}
		go func() { _ = h.http3Server.ServeListener(quicListener) }()
	}

	return nil
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		common.PtrOrNil(h.httpServer),
		common.PtrOrNil(h.http3Server),
		h.httpTLSConfig,
		h.http3TLSConfig,
	)
}

func (h *Inbound) UpdateUsers(users []option.TrustTunnelUser) {
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		userMap[u.Name] = u.Password
	}
	h.service.UpdateUsers(userMap)
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
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
