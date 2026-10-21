//go:build with_utls

package trusttunnel

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// resolveCacheTTL — сколько держим резолв домена без повторного запроса к DNS.
const (
	resolveCacheTTL = 30 * time.Second
	resolveCacheMax = 4096
)

type tcpCongestionDialer struct {
	N.Dialer
	congestionControl string
}

func (d tcpCongestionDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		trusttunnel.SetTCPCongestionControl(tcpConn, d.congestionControl)
	}
	return conn, nil
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TrustTunnelOutboundOptions](registry, C.TypeTrustTunnel, NewOutbound)
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type resolveCacheEntry struct {
	addr    M.Socksaddr
	expires time.Time
}

type Outbound struct {
	outbound.Adapter
	logger       logger.ContextLogger
	dnsRouter    adapter.DNSRouter
	client       *trusttunnel.MultiplexClient
	resolveMu    sync.Mutex
	resolveCache map[string]resolveCacheEntry
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if err := validateUDPPadding(options.UDPPadding); err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	if options.CongestionController != "" {
		outboundDialer = tcpCongestionDialer{Dialer: outboundDialer, congestionControl: options.CongestionController}
	}
	serverAddr := options.ServerOptions.Build()
	networkList := options.Network.Build()
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	udpPaddingMin, udpPaddingMax := paddingRange(options.UDPPadding)
	clientOpts := trusttunnel.ClientOptions{
		Dialer:                  outboundDialer,
		TLSConfig:               tlsConfig,
		Server:                  serverAddr,
		Username:                options.Username,
		Password:                options.Password,
		QUIC:                    options.QUIC,
		DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		CongestionControl:       options.CongestionController,
		CWND:                    options.CWND,
		Logger:                  logger,
		UDPPaddingMin:           udpPaddingMin,
		UDPPaddingMax:           udpPaddingMax,
	}
	// Раньше без multiplex.enabled создавался голый *Client — у него нет
	// самовосстановления: Close() убивает его насовсем, и любую сетевую
	// проблему (см. InterfaceUpdated/roundTrip ниже) пришлось бы чинить
	// вручную пересозданием объекта на уровне Outbound (лишний мьютекс и
	// код, которого нет в hysteria2/tuic/ssh). MultiplexClient это умеет
	// «из коробки»: Close() обнуляет пул, а следующий Dial/ListenPacket сам
	// поднимает свежий *Client. Поэтому заводим MultiplexClient всегда;
	// maxConnections=1 без явного multiplex.enabled сохраняет прежнее
	// поведение (один транспорт, без пулинга соединений) — 0/0/0 включил
	// бы в NewMultiplexClient дефолтный пул на 8 соединений, что было бы
	// неожиданной сменой поведения для тех, кто multiplex не просил.
	maxConnections, minStreams, maxStreams := 1, 0, 0
	if options.Multiplex != nil && options.Multiplex.Enabled {
		maxConnections = options.Multiplex.MaxConnections
		minStreams = options.Multiplex.MinStreams
		maxStreams = options.Multiplex.MaxStreams
	}
	clientOpts.MaxConnections = maxConnections
	clientOpts.MinStreams = minStreams
	clientOpts.MaxStreams = maxStreams
	client, err := trusttunnel.NewMultiplexClient(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:      outbound.NewAdapterWithDialerOptions(C.TypeTrustTunnel, tag, networkList, options.DialerOptions),
		logger:       logger,
		dnsRouter:    service.FromContext[adapter.DNSRouter](ctx),
		client:       client,
		resolveCache: make(map[string]resolveCacheEntry),
	}, nil
}

// resolveDestination резолвит destination.Fqdn в IP через роутер, если Addr
// ещё не выставлен. Протокол TrustTunnel для UDP адресует только по IP
// (16-байтовое поле в заголовке, без домена) — в отличие от TCP, где домен
// уходит как Host в CONNECT и резолвится сервером. Без этого шага пакеты с
// доменом без резолва (например, после QUIC-сниффинга на голом UDP-потоке
// tun, до похода в DNS) падали с "only support IP". Результат кэшируется на
// resolveCacheTTL, см. комментарий там.
func (h *Outbound) resolveDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.Addr.IsValid() || !destination.IsFqdn() {
		return destination, nil
	}
	now := time.Now()
	h.resolveMu.Lock()
	if entry, ok := h.resolveCache[destination.Fqdn]; ok && now.Before(entry.expires) {
		h.resolveMu.Unlock()
		return M.Socksaddr{Addr: entry.addr.Addr, Port: destination.Port}, nil
	}
	h.resolveMu.Unlock()

	if h.dnsRouter == nil {
		return M.Socksaddr{}, E.New("dns router not available to resolve ", destination.Fqdn)
	}
	addresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
	if err != nil {
		return M.Socksaddr{}, E.Cause(err, "resolve ", destination.Fqdn)
	}
	if len(addresses) == 0 {
		return M.Socksaddr{}, E.New("no address resolved for ", destination.Fqdn)
	}
	resolved := M.Socksaddr{Addr: addresses[0], Port: destination.Port}

	h.resolveMu.Lock()
	if len(h.resolveCache) >= resolveCacheMax {
		// shortcut: full sweep of expired entries on overflow, fine at this size; use an LRU if the bound is raised a lot.
		for k, e := range h.resolveCache {
			if !now.Before(e.expires) {
				delete(h.resolveCache, k)
			}
		}
		if len(h.resolveCache) >= resolveCacheMax {
			clear(h.resolveCache)
		}
	}
	h.resolveCache[destination.Fqdn] = resolveCacheEntry{addr: resolved, expires: now.Add(resolveCacheTTL)}
	h.resolveMu.Unlock()

	return resolved, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.Dial(ctx, destination.String())
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		resolved, err := h.resolveDestination(ctx, destination)
		if err != nil {
			return nil, err
		}
		conn, err := h.client.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, resolved), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &resolvingPacketConn{PacketConn: conn, outbound: h, ctx: ctx}, nil
}

// InterfaceUpdated вызывается роутером при смене дефолтного сетевого
// интерфейса (Wi-Fi↔мобильная сеть, смена вышки с новым внешним IP и т.п.),
// как и в hysteria2/hysteria/tuic/ssh outbound. Старое HTTP/2- или
// QUIC-соединение после такой смены на мобильных сетях почти всегда мертво
// (carrier NAT молча дропает маппинг, без RST/FIN), а h2/h3 сами узнают об
// этом не сразу. MultiplexClient.Close() обнуляет пул, следующий
// Dial()/ListenPacket() сам поднимет свежий транспорт — как и у остальных
// протоколов, без ручного пересоздания объекта здесь.
func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.Reset()
	h.resolveMu.Lock()
	clear(h.resolveCache)
	h.resolveMu.Unlock()
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(h.client.Close)
	return nil
}

var (
	_ N.NetPacketConn = (*resolvingPacketConn)(nil)
	_ N.FrontHeadroom = (*resolvingPacketConn)(nil)
)

// resolvingPacketConn резолвит Fqdn-only destination на каждый WriteTo/WritePacket,
// т.к. в этом режиме (используется NAT-стеком tun) destination меняется
// от вызова к вызову и не зафиксирован один раз при создании соединения.
type resolvingPacketConn struct {
	net.PacketConn
	outbound *Outbound
	ctx      context.Context
}

func (c *resolvingPacketConn) FrontHeadroom() int {
	if fh, ok := c.PacketConn.(N.FrontHeadroom); ok {
		return fh.FrontHeadroom()
	}
	return 0
}

func (c *resolvingPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if npc, ok := c.PacketConn.(N.NetPacketConn); ok {
		return npc.ReadPacket(buffer)
	}
	destination = M.Socksaddr{}
	n, addr, err := c.PacketConn.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return destination, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr), nil
}

func (c *resolvingPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsFqdn() {
		if npc, ok := c.PacketConn.(N.NetPacketConn); ok {
			return npc.WritePacket(buffer, destination)
		}
		defer buffer.Release()
		_, err := c.PacketConn.WriteTo(buffer.Bytes(), destination.UDPAddr())
		return err
	}
	ctx := c.ctx
	var cancel context.CancelFunc
	if ctx == nil || ctx.Err() != nil {
		ctx, cancel = context.WithTimeout(context.Background(), C.TCPTimeout)
		defer cancel()
	}
	resolved, err := c.outbound.resolveDestination(ctx, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	if npc, ok := c.PacketConn.(N.NetPacketConn); ok {
		return npc.WritePacket(buffer, resolved)
	}
	defer buffer.Release()
	_, err = c.PacketConn.WriteTo(buffer.Bytes(), resolved.UDPAddr())
	return err
}

func (c *resolvingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsFqdn() {
		return c.PacketConn.WriteTo(p, addr)
	}
	ctx := c.ctx
	var cancel context.CancelFunc
	if ctx == nil || ctx.Err() != nil {
		ctx, cancel = context.WithTimeout(context.Background(), C.TCPTimeout)
		defer cancel()
	}
	resolved, err := c.outbound.resolveDestination(ctx, destination)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, resolved.UDPAddr())
}
