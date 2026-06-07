package option

import (
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

type MTProxyInboundOptions struct {
	ListenOptions
	Users                       []MTProxyUser      `json:"users,omitempty"`
	Concurrency                 uint               `json:"concurrency,omitempty"`
	DomainFrontingPort          uint               `json:"domain_fronting_port,omitempty"`
	DomainFrontingHost          string             `json:"domain_fronting_host,omitempty"`
	DomainFrontingProxyProtocol bool               `json:"domain_fronting_proxy_protocol,omitempty"`
	PreferIP                    string             `json:"prefer_ip,omitempty"`
	AutoUpdate                  bool               `json:"auto_update,omitempty"`
	AllowFallbackOnUnknownDC    bool               `json:"allow_fallback_on_unknown_dc,omitempty"`
	TolerateTimeSkewness        badoption.Duration `json:"tolerate_time_skewness,omitempty"`
	IdleTimeout                 badoption.Duration `json:"idle_timeout,omitempty"`
	HandshakeTimeout            badoption.Duration `json:"handshake_timeout,omitempty"`
	DoppelGangerURLs            []string           `json:"doppelganger_urls,omitempty"`
	DoppelGangerPerRaid         uint               `json:"doppelganger_per_raid,omitempty"`
	DoppelGangerEach            badoption.Duration `json:"doppelganger_each,omitempty"`
	DoppelGangerDRS             bool               `json:"doppelganger_drs,omitempty"`
	ThrottleMaxConnections      uint               `json:"throttle_max_connections,omitempty"`
	ThrottleCheckInterval       badoption.Duration `json:"throttle_check_interval,omitempty"`
}

func (o *MTProxyInboundOptions) GetConcurrency() uint {
	if o.Concurrency == 0 {
		return 8192
	}
	return o.Concurrency
}

func (o *MTProxyInboundOptions) GetDomainFrontingPort() uint {
	if o.DomainFrontingPort == 0 {
		return 443
	}
	return o.DomainFrontingPort
}

func (o *MTProxyInboundOptions) GetPreferIP() string {
	if o.PreferIP == "" {
		return "prefer-ipv4"
	}
	return o.PreferIP
}

func (o *MTProxyInboundOptions) GetIdleTimeout() time.Duration {
	if o.IdleTimeout == 0 {
		return 5 * time.Minute
	}
	return o.IdleTimeout.Build()
}

func (o *MTProxyInboundOptions) GetHandshakeTimeout() time.Duration {
	if o.HandshakeTimeout == 0 {
		return 10 * time.Second
	}
	return o.HandshakeTimeout.Build()
}

func (o *MTProxyInboundOptions) GetDoppelGangerPerRaid() uint {
	if o.DoppelGangerPerRaid == 0 {
		return 10
	}
	return o.DoppelGangerPerRaid
}

func (o *MTProxyInboundOptions) GetDoppelGangerEach() time.Duration {
	if o.HandshakeTimeout == 0 {
		return 6 * time.Hour
	}
	return o.DoppelGangerEach.Build()
}

func (o *MTProxyInboundOptions) GetThrottleCheckInterval() time.Duration {
	if o.ThrottleCheckInterval == 0 {
		return 5 * time.Second
	}
	return o.ThrottleCheckInterval.Build()
}

type MTProxyUser struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}
