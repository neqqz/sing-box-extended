package option

import "github.com/sagernet/sing/common/json/badoption"

// TrustTunnelPaddingOptions задаёт диапазон [Min, Max] байт случайного
// паддинга для полезной нагрузки UDP-пакетов протокола.
type TrustTunnelPaddingOptions struct {
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
}

// TrustTunnelTimingOptions задаёт умный джиттер по времени на фазе установления соединения.
// Если MaxMS > 0, перед отправкой первых Packets пакетов (по умолчанию 5) добавляется
// случайная задержка в [MinMS, MaxMS] мс. Защищает от timing-анализа рукопожатия DPI,
// при этом автоматически отключается на фазе потоковой передачи (bulk transfer),
// не снижая скорость соединения и не ломая pacing BBR/Cubic.
type TrustTunnelTimingOptions struct {
	MinMS   int `json:"min_ms,omitempty"`
	MaxMS   int `json:"max_ms,omitempty"`
	Packets int `json:"packets,omitempty"`
}

type TrustTunnelInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users                        []TrustTunnelUser          `json:"users,omitempty"`
	Network                      NetworkList                `json:"network,omitempty"`
	CongestionController         string                     `json:"congestion_controller,omitempty"`
	CWND                         int                        `json:"cwnd,omitempty"`
	DisablePathMTUDiscovery      bool                       `json:"disable_path_mtu_discovery,omitempty"`
	Timing                       *TrustTunnelTimingOptions  `json:"timing,omitempty"`
	ClientRandomPrefix           badoption.Listable[string] `json:"client_random_prefix,omitempty"`
	ClientRandomPrefixSecret     badoption.Listable[string] `json:"client_random_prefix_secret,omitempty"`
	ClientRandomPrefixLen        int                        `json:"client_random_prefix_len,omitempty"`
	ClientRandomPrefixFile       string                     `json:"client_random_prefix_file,omitempty"`
	ClientRandomPrefixSecretFile string                     `json:"client_random_prefix_secret_file,omitempty"`
	FallbackServer               string                     `json:"fallback_server,omitempty"`
	FallbackSNIPort              uint16                     `json:"fallback_sni_port,omitempty"`
	AllowedSNI                   []string                   `json:"allowed_sni,omitempty"`
	UDPPadding                   *TrustTunnelPaddingOptions `json:"udp_padding,omitempty"`
}

type TrustTunnelUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type TrustTunnelMultiplexOptions struct {
	Enabled        bool `json:"enabled,omitempty"`
	MaxConnections int  `json:"max_connections,omitempty"`
	MinStreams     int  `json:"min_streams,omitempty"`
	MaxStreams     int  `json:"max_streams,omitempty"`
}

type TrustTunnelOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Username                string                       `json:"username,omitempty"`
	Password                string                       `json:"password,omitempty"`
	Network                 NetworkList                  `json:"network,omitempty"`
	QUIC                    bool                         `json:"quic,omitempty"`
	CongestionController    string                       `json:"congestion_controller,omitempty"`
	CWND                    int                          `json:"cwnd,omitempty"`
	DisablePathMTUDiscovery bool                         `json:"disable_path_mtu_discovery,omitempty"`
	Timing                  *TrustTunnelTimingOptions    `json:"timing,omitempty"`
	Multiplex               *TrustTunnelMultiplexOptions `json:"multiplex,omitempty"`
	UDPPadding              *TrustTunnelPaddingOptions   `json:"udp_padding,omitempty"`
	HealthCheck             bool                         `json:"health_check,omitempty"`
}
