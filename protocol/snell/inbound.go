package snell

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/snell"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SnellInboundOptions](registry, C.TypeSnell, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  *snell.Service
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellInboundOptions) (adapter.Inbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell requires psk")
	}
	udpEnabled := common.Contains(options.Network.Build(), N.NetworkUDP)
	obfsMode := ""
	if options.Obfs != nil {
		obfsMode = options.Obfs.Mode
	}
	in := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeSnell, tag),
		router:  router,
		logger:  logger,
	}
	service, err := snell.NewService(snell.ServiceOptions{
		PSK:      []byte(options.PSK),
		Version:  options.Version,
		ObfsMode: obfsMode,
		UDP:      udpEnabled,
		Logger:   logger,
		Handler:  (*inboundHandler)(in),
	})
	if err != nil {
		return nil, err
	}
	in.service = service
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: in,
	})
	return in, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.service.NewConnection(ctx, conn, metadata.Source)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type inboundHandler Inbound

func (h *inboundHandler) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, clientID string) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	metadata.Destination = destination
	if clientID != "" {
		metadata.User = clientID
		h.logger.InfoContext(ctx, "[", clientID, "] inbound connection to ", destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	done := make(chan struct{})
	h.router.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) {
		close(done)
	}))
	<-done
}

func (h *inboundHandler) NewPacketConnection(ctx context.Context, conn net.PacketConn, source M.Socksaddr, clientID string) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	metadata.Source = source
	if clientID != "" {
		metadata.User = clientID
		h.logger.InfoContext(ctx, "[", clientID, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection")
	}
	done := make(chan struct{})
	h.router.RoutePacketConnectionEx(ctx, bufio.NewPacketConn(conn), metadata, N.OnceClose(func(error) {
		close(done)
	}))
	<-done
}
