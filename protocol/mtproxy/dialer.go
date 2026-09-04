package mtproxy

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type Dialer struct {
	handler adapter.ConnectionHandlerFunc
}

func NewDialer(handler adapter.ConnectionHandlerFunc) *Dialer {
	return &Dialer{handler}
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	inConn, outConn := net.Pipe()
	var metadata adapter.InboundContext
	if streamContext, ok := ctx.(streamContext); ok {
		metadata.Source = M.SocksaddrFromNet(streamContext.ClientAddr())
		metadata.User = streamContext.SecretName()
	}
	metadata.Destination = M.ParseSocksaddr(address)
	d.handler(ctx, inConn, metadata, func(error) {})
	return outConn, nil
}

type streamContext interface {
	ClientAddr() net.Addr
	SecretName() string
}
