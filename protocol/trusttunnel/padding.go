package trusttunnel

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
)

func paddingRange(p *option.TrustTunnelPaddingOptions) (min, max int) {
	if p == nil {
		return 0, 0
	}
	return p.Min, p.Max
}

func validateUDPPadding(udp *option.TrustTunnelPaddingOptions) error {
	min, max := paddingRange(udp)
	return trusttunnel.ValidatePadding("udp_padding", min, max, trusttunnel.MaxUDPPadding)
}

func timingRange(t *option.TrustTunnelTimingOptions) (minMS, maxMS, packets int) {
	if t == nil {
		return 0, 0, 0
	}
	return t.MinMS, t.MaxMS, t.Packets
}
