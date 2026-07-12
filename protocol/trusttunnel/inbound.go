package trusttunnel

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
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
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

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
	next       http.Handler
	allowedSNI []string
	logger     logger.ContextLogger
}

func newSNIMiddleware(next http.Handler, allowed []string, log logger.ContextLogger) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	return &sniMiddleware{next: next, allowedSNI: allowed, logger: log}
}

func (m *sniMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	if !checkSNI(m.allowedSNI, sni) {
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
	h2Server       *http2.Server
	http3Server    *http3.Server
	httpTLSConfig  tls.ServerConfig
	http3TLSConfig tls.ServerConfig
	network        []string
	randomPrefix   []byte
	randomMask     []byte
	// handshakeSem ограничивает число ОДНОВРЕМЕННО выполняемых TLS
	// handshake'ов. Раньше go h.serveConn(...) запускался без всякого
	// лимита — при burst'е из сотни+ соединений сразу (типичный триггер:
	// рестарт сервера или клиента, когда весь пул переподключается разом)
	// все эти горутины одновременно грызли CPU на RSA/ECDHE, и часть из
	// них честно не укладывалась в дедлайн просто из-за нехватки CPU-time
	// на всех разом — сколько дедлайн ни повышай, при настоящей перегрузке
	// это лечит симптом, а не причину. Семафор превращает "все дерутся за
	// CPU одновременно и часть проигрывает по таймауту" в "обрабатываем
	// по очереди с полной отдачей CPU каждому" — суммарно burst
	// прожёвывается быстрее и с кратно меньшим числом реальных отказов.
	handshakeSem chan struct{}
}

// DefaultMaxConcurrentHandshakes — сколько TLS handshake'ов обрабатываем
// одновременно. RSA/ECDHE handshake CPU-bound, поэтому лимит держим
// в районе числа ядер, а не по числу соединений — иначе просто
// переносим ту же перегрузку с "конкуренция за CPU" на "конкуренция за
// семафор" без выигрыша.
var DefaultMaxConcurrentHandshakes = max(runtime.NumCPU()*4, 16)

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
		handshakeSem: make(chan struct{}, DefaultMaxConcurrentHandshakes),
	}
	service := trusttunnel.NewService(trusttunnel.ServiceOptions{
		Ctx:           ctx,
		Logger:        logger,
		Handler:       (*inboundHandler)(h),
		UDPPaddingMin: common.PtrValueOrDefault(options.UDPPaddingMin),
		UDPPaddingMax: common.PtrValueOrDefault(options.UDPPaddingMax),
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

	// Для TCP SNI проверяется вручную в serveConn (см. ниже) — там надёжный
	// источник данных (tlsConn.ConnectionState()), в отличие от r.TLS в
	// net/http. sniMiddleware держим только для QUIC/H3: там r.TLS заполняет
	// сам quic-go/http3, и это надёжно.
	h3Handler := newSNIMiddleware(h.service, h.options.AllowedSNI, h.logger)

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
		checkedListener, err := trusttunnel.NewPrefixListener(rawListener, h.options.ClientRandomPrefix, h.options.FallbackServer, h.logger)
		if err != nil {
			return err
		}
		if err = h.httpTLSConfig.Start(); err != nil {
			return err
		}

		h.httpServer = &http.Server{
			Handler:           h.service,
			BaseContext:       func(net.Listener) context.Context { return h.ctx },
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       trusttunnel.DefaultSessionTimeout*2 + 10*time.Second,
		}
		h.h2Server = &http2.Server{
			IdleTimeout: trusttunnel.DefaultSessionTimeout * 2,
			// Дефолт x/net/http2 — 1 MB на стрим/соединение. При RTT
			// в несколько сотен мс (типично для маршрута до зарубежного
			// VPS из РФ) это даёт потолок throughput = window/RTT, что
			// на практике режет скорость аплоада крупных файлов одним
			// стримом (например, артефактов в GitHub Actions) до
			// заметно меньше канала. Поднимаем окно под BDP:
			// window >= целевая_скорость_байт/с * RTT_сек.
			MaxUploadBufferPerStream:     8 << 20,  // 8 MB
			MaxUploadBufferPerConnection: 16 << 20, // 16 MB
		}
		// ВАЖНО: net/http.Server.Serve() определяет ALPN-протокол и решает,
		// звать ли http2.Server, через жёсткий type assertion c.rwc.(*tls.Conn)
		// (см. net/http/server.go, conn.serve()). aTLS.NewListener оборачивает
		// сырое соединение в *aTLS.LazyConn — это НЕ *tls.Conn и не реализует
		// ConnectionState(), поэтому stdlib ALPN-диспатч на такой обёртке
		// молча не срабатывает и всё уходит в HTTP/1.1, даже если клиент
		// согласовал h2 на TLS-уровне. Поэтому здесь TLS-хендшейк и ALPN
		// разбираются вручную, минуя http.Server для h2-соединений.
		// SNI для этого пути проверяется в serveConn, поэтому передаём
		// h.service напрямую, без sniMiddleware.
		go h.acceptLoop(checkedListener, h.service)
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
			Handler: h3Handler,
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
			MaxIncomingStreams:       1 << 60,
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

// acceptLoop принимает TCP-соединения, прошедшие prefix-check, выполняет TLS
// хендшейк вручную и диспетчеризует по согласованному ALPN: h2 идёт прямиком
// в http2.Server.ServeConn, всё остальное — в http.Server через одноразовый
// listener. Это обходит жёсткий type assertion c.rwc.(*tls.Conn) в net/http,
// который никогда не срабатывает на *aTLS.LazyConn.
func (h *Inbound) acceptLoop(rawListener net.Listener, handler http.Handler) {
	for {
		rawConn, err := rawListener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				h.logger.Error("trusttunnel: accept: ", err)
			}
			return
		}
		go h.serveConn(rawConn, handler)
	}
}

func (h *Inbound) serveConn(rawConn net.Conn, handler http.Handler) {
	// ВАЖНО: раньше здесь стояло 10*time.Second — короче, чем клиентский
	// C.TCPTimeout (15s), которым клиент ограничивает весь дозвон целиком
	// (TCP+TLS+первый ответ). На стабильной сети разницы не видно, но на
	// мобильной, где TLS-хендшейку иногда честно нужно 10-14s из-за
	// ретрансмитов (RTO 1s→2s→4s→8s при потере пары пакетов), СЕРВЕР
	// обрывал ещё живой, но чуть медленный хендшейк раньше, чем клиент
	// вообще решил бы сдаться — то есть сервер сам создавал часть тех
	// "context canceled"/"operation was canceled" на клиенте, которые
	// выглядели как проблема клиента. 20s даёт запас сверх клиентских 15s.
	ctx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
	defer cancel()
	// Ждём слот в семафоре, но не дольше того же общего дедлайна — если
	// burst настолько большой, что мы не успеваем добраться до хендшейка
	// даже за 20s, честно отдаём ту же ошибку, что вызывающий уже привык
	// видеть, вместо того чтобы копить неограниченную очередь горутин.
	select {
	case h.handshakeSem <- struct{}{}:
		defer func() { <-h.handshakeSem }()
	case <-ctx.Done():
		_ = rawConn.Close()
		h.logger.Debug("trusttunnel: TLS handshake failed: ", ctx.Err())
		return
	}
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
	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		h.h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
			Context: h.ctx,
			Handler: handler,
		})
	default:
		if sErr := h.httpServer.Serve(newSingleConnListener(tlsConn)); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) && !errors.Is(sErr, io.EOF) {
			h.logger.Debug("trusttunnel: H1 conn: ", sErr)
		}
	}
}

// singleConnListener отдаёт ровно одно уже установленное соединение,
// чтобы прогнать его через стандартный http.Server как HTTP/1.1.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c == nil {
		<-l.done
		return nil, io.EOF
	}
	return c, nil
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

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
