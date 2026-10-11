package trusttunnel

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trusttunnel"
)

// paddingRange safely reads Min/Max out of an optional *TrustTunnelPaddingOptions.
// nil (not configured) behaves exactly like the previous scalar 0/0 default —
// padding disabled.
func paddingRange(p *option.TrustTunnelPaddingOptions) (min, max int) {
	if p == nil {
		return 0, 0
	}
	return p.Min, p.Max
}

// timingRange safely reads MinMS/MaxMS out of an optional *TrustTunnelTimingOptions.
// nil (not configured) behaves exactly like the previous scalar 0/0 default —
// timing jitter disabled.
func timingRange(t *option.TrustTunnelTimingOptions) (minMS, maxMS int) {
	if t == nil {
		return 0, 0
	}
	return t.MinMS, t.MaxMS
}

// validatePaddings fails startup on padding ranges that would corrupt the
// stream (see trusttunnel.ValidatePadding).
func validatePaddings(udp, data, packet *option.TrustTunnelPaddingOptions) error {
	for _, c := range []struct {
		name  string
		p     *option.TrustTunnelPaddingOptions
		limit int
	}{
		{"udp_padding", udp, trusttunnel.MaxUDPPadding},
		{"data_padding", data, trusttunnel.MaxDataPadding},
		// shortcut: packet_padding only gets the sanity check; the real ceiling is the path MTU, unknown here.
		{"packet_padding", packet, trusttunnel.MaxUDPPadding},
	} {
		min, max := paddingRange(c.p)
		if err := trusttunnel.ValidatePadding(c.name, min, max, c.limit); err != nil {
			return err
		}
	}
	return nil
}
