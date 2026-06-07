//go:build with_openvpn

package openvpn

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	ovpn "github.com/sagernet/sing-box/transport/openvpn"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.OpenVPNOutboundOptions](registry, C.TypeOpenVPN, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	tunnel    *ovpn.Tunnel
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.OpenVPNOutboundOptions) (adapter.Outbound, error) {
	tlsConfig, err := tls.NewOpenVPNClient(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var tlsKey []byte
	keyDirection := -1
	if options.TLSAuth != "" || options.TLSAuthPath != "" {
		tlsAuth := options.TLSAuth
		if tlsAuth == "" {
			data, err := os.ReadFile(options.TLSAuthPath)
			if err != nil {
				return nil, E.Cause(err, "read tls_auth_path")
			}
			tlsAuth = string(data)
		}
		tlsKey = []byte(tlsAuth)
		keyDirection = options.KeyDirection
	} else {
		tlsCrypt := options.TLSCrypt
		if tlsCrypt == "" && options.TLSCryptPath != "" {
			data, err := os.ReadFile(options.TLSCryptPath)
			if err != nil {
				return nil, E.Cause(err, "read tls_crypt_path")
			}
			tlsCrypt = string(data)
		}
		tlsKey = []byte(tlsCrypt)
	}
	clientConfig := &ovpn.ClientConfig{
		Proto:        options.Proto,
		Cipher:       options.Cipher,
		Auth:         options.Auth,
		Username:     options.Username,
		Password:     options.Password,
		KeyDirection: keyDirection,
		TLSCrypt:     tlsKey,
		TLSCryptV2:   options.TLSCryptV2,
	}
	if err := clientConfig.Prepare(); err != nil {
		return nil, E.Cause(err, "invalid openvpn config")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	o := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeOpenVPN, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:       ctx,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		logger:    logger,
	}
	tunnel, err := ovpn.NewTunnel(ctx, logger, ovpn.TunnelOptions{
		System: options.System,
		Name:   options.Name,
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
				BindInterface: interfaceName,
			}))
		},
		Dialer:         outboundDialer,
		Servers:        options.Servers,
		TLSConfig:      tlsConfig,
		Config:         clientConfig,
		AllowedAddress: options.AllowedIPs,
		ReconnectDelay: time.Duration(options.ReconnectDelay),
		PingInterval:   time.Duration(options.PingInterval),
	})
	if err != nil {
		return nil, err
	}
	o.tunnel = tunnel
	return o, nil
}

func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	return o.tunnel.Start()
}

func (o *Outbound) Close() error {
	if o.tunnel != nil {
		return o.tunnel.Close()
	}
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsDomain() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.tunnel, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return o.tunnel.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, o.tunnel, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
			return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
		}
		return packetConn, nil
	}
	return o.tunnel.ListenPacket(ctx, destination)
}
