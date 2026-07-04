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
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TrustTunnelOutboundOptions](registry, C.TypeTrustTunnel, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	router adapter.Router
	client trusttunnel.Dialer
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrustTunnelOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	serverAddr := options.ServerOptions.Build()
	networkList := options.Network.Build()
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	clientOpts := trusttunnel.ClientOptions{
		Dialer:            outboundDialer,
		TLSConfig:         tlsConfig,
		Server:            serverAddr,
		Username:          options.Username,
		Password:          options.Password,
		QUIC:              options.QUIC,
		CongestionControl: options.CongestionController,
		CWND:              options.CWND,
		Logger:            logger,
		HealthCheck:       options.HealthCheck,
	}
	var client trusttunnel.Dialer
	if options.Multiplex != nil && options.Multiplex.Enabled {
		clientOpts.MaxConnections = options.Multiplex.MaxConnections
		clientOpts.MinStreams = options.Multiplex.MinStreams
		clientOpts.MaxStreams = options.Multiplex.MaxStreams
		client, err = trusttunnel.NewMultiplexClient(ctx, clientOpts)
	} else {
		client, err = trusttunnel.NewClient(ctx, clientOpts)
	}
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeTrustTunnel, tag, networkList, options.DialerOptions),
		logger:  logger,
		router:  router,
		client:  client,
	}, nil
}

// resolveDestination резолвит destination.Fqdn в IP через роутер, если Addr
// ещё не выставлен. Протокол TrustTunnel для UDP адресует только по IP
// (16-байтовое поле в заголовке, без домена) — в отличие от TCP, где домен
// уходит как Host в CONNECT и резолвится сервером. Без этого шага пакеты с
// доменом без резолва (например, после QUIC-сниффинга на голом UDP-потоке
// tun, до похода в DNS) падали с "only support IP".
func (h *Outbound) resolveDestination(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.Addr.IsValid() || !destination.IsFqdn() {
		return destination, nil
	}
	addresses, err := h.router.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
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
	return &resolvingPacketConn{PacketConn: conn, outbound: h, ctx: ctx}, nil
}

func (h *Outbound) Close() error {
	return h.client.Close()
}

// resolvingPacketConn резолвит Fqdn-only destination на каждый WriteTo,
// т.к. в этом режиме (используется NAT-стеком tun) destination меняется
// от вызова к вызову и не зафиксирован один раз при создании соединения.
type resolvingPacketConn struct {
	net.PacketConn
	outbound *Outbound
	ctx      context.Context
}

func (c *resolvingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	resolved, err := c.outbound.resolveDestination(c.ctx, destination)
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, resolved.UDPAddr())
}
