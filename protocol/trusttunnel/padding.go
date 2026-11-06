package trusttunnel

import (
	"fmt"

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

const (
	maxTimingDelayMS = 60_000
	maxTimingPackets = 64
)

func validateTiming(t *option.TrustTunnelTimingOptions) error {
	if t == nil {
		return nil
	}
	if t.MinMS < 0 || t.MaxMS < t.MinMS || t.MaxMS > maxTimingDelayMS {
		return fmt.Errorf("timing: need 0 <= min_ms <= max_ms <= %d, got [%d, %d]", maxTimingDelayMS, t.MinMS, t.MaxMS)
	}
	if t.Packets < 0 || t.Packets > maxTimingPackets {
		return fmt.Errorf("timing: packets must be between 0 and %d, got %d", maxTimingPackets, t.Packets)
	}
	return nil
}

func timingRange(t *option.TrustTunnelTimingOptions) (minMS, maxMS, packets int) {
	if t == nil {
		return 0, 0, 0
	}
	return t.MinMS, t.MaxMS, t.Packets
}
