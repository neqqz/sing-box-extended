//go:build with_snell

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/snell"
)

func registerSnellInbound(registry *inbound.Registry) {
	snell.RegisterInbound(registry)
}

func registerSnellOutbound(registry *outbound.Registry) {
	snell.RegisterOutbound(registry)
}
