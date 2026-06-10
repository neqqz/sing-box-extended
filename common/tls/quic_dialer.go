package tls

import (
	"context"
	"net"

	"github.com/sagernet/quic-go"
)

// QUICDialer is implemented by TLS configs that support QUIC with custom
// ClientRandom patching (e.g. UTLSClientConfig with ClientRandomPrefix).
// When tls.Config implements this interface, trusttunnel QUIC transport
// uses DialEarly directly instead of qtls.DialEarly, ensuring
// ClientRandomPrefix is applied to the QUIC handshake.
type QUICDialer interface {
	DialEarly(ctx context.Context, conn net.PacketConn, addr net.Addr, quicConfig *quic.Config) (*quic.Conn, error)
}
