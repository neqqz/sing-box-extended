package trusttunnel

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
	"github.com/sagernet/sing-box/transport/trusttunnel/obfs"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

type tcpTimingDialer struct {
	N.Dialer
	congestionControl string
	minMS             int
	maxMS             int
	packets           int
}

func (d tcpTimingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	if N.NetworkName(network) == N.NetworkTCP {
		if d.congestionControl != "" {
			trusttunnel.SetTCPCongestionControl(conn, d.congestionControl)
		}
		if d.maxMS > 0 {
			return obfs.NewJitterConn(conn, d.minMS, d.maxMS, d.packets), nil
		}
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

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	dnsRouter adapter.DNSRouter
	client    *trusttunnel.MultiplexClient
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
	timingMin, timingMax, timingPackets := timingRange(options.Timing)
	if options.CongestionController != "" || timingMax > 0 {
		outboundDialer = tcpTimingDialer{
			Dialer:            outboundDialer,
			congestionControl: options.CongestionController,
			minMS:             timingMin,
			maxMS:             timingMax,
			packets:           timingPackets,
		}
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
		HealthCheck:             options.HealthCheck,
		UDPPaddingMin:           udpPaddingMin,
		UDPPaddingMax:           udpPaddingMax,
		JitterMinMS:             timingMin,
		JitterMaxMS:             timingMax,
		JitterPackets:           timingPackets,
		TimeFunc:                ntp.TimeFuncFromContext(ctx),
		UserAgent:               options.UserAgent,
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
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeTrustTunnel, tag, networkList, options.DialerOptions),
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		client:    client,
	}, nil
}

// resolveDestination резолвит destination.Fqdn в IP через роутер, если Addr ещё не выставлен.
func (h *Outbound) resolveDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.IsIP() {
		return destination, nil
	}
	if !destination.IsDomain() {
		return destination, nil
	}
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
	return M.Socksaddr{Addr: addresses[0], Port: destination.Port}, nil
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
	npc, _ := conn.(N.NetPacketConn)
	return &resolvingPacketConn{PacketConn: conn, npc: npc, outbound: h, ctx: ctx}, nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.Reset()
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
	npc      N.NetPacketConn
	outbound *Outbound
	ctx      context.Context
}

func (c *resolvingPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *resolvingPacketConn) FrontHeadroom() int {
	if fh, ok := c.PacketConn.(N.FrontHeadroom); ok {
		return fh.FrontHeadroom()
	}
	return 0
}

func (c *resolvingPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.npc != nil {
		return c.npc.ReadPacket(buffer)
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
	if destination.IsIP() {
		if c.npc != nil {
			return c.npc.WritePacket(buffer, destination)
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
	if c.npc != nil {
		return c.npc.WritePacket(buffer, resolved)
	}
	defer buffer.Release()
	_, err = c.PacketConn.WriteTo(buffer.Bytes(), resolved.UDPAddr())
	return err
}

func (c *resolvingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if destination.IsIP() {
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
