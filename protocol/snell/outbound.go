package snell

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
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

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *snell.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell requires psk")
	}
	version := options.Version
	if version == 0 {
		version = snell.DefaultSnellVersion
	}
	if version == snell.Version5 {
		version = snell.Version4
	}
	udpEnabled := common.Contains(options.Network.Build(), N.NetworkUDP)
	switch version {
	case snell.Version1, snell.Version2:
		if udpEnabled {
			return nil, fmt.Errorf("snell version %d does not support UDP", version)
		}
	case snell.Version3, snell.Version4:
	default:
		return nil, fmt.Errorf("snell version error: %d", version)
	}
	reuse := version == snell.Version2 || (version == snell.Version4 && options.Reuse)
	obfsMode := ""
	obfsHost := "bing.com"
	if options.Obfs != nil {
		switch options.Obfs.Mode {
		case "", "tls", "http":
			obfsMode = options.Obfs.Mode
		default:
			return nil, fmt.Errorf("snell obfs mode error: %s", options.Obfs.Mode)
		}
		if options.Obfs.Host != "" {
			obfsHost = options.Obfs.Host
		}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	client := snell.NewClient(snell.ClientOptions{
		Dialer:   outboundDialer,
		Server:   options.ServerOptions.Build(),
		PSK:      []byte(options.PSK),
		Version:  version,
		Reuse:    reuse,
		ObfsMode: obfsMode,
		ObfsHost: obfsHost,
	})
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, options.Network.Build(), options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := h.client.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx, destination)
}
