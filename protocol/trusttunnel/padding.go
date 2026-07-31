package trusttunnel

import "github.com/sagernet/sing-box/option"

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
