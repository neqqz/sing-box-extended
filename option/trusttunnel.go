package option

type TrustTunnelInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users                []TrustTunnelUser `json:"users,omitempty"`
	Network              NetworkList       `json:"network,omitempty"`
	CongestionController string            `json:"congestion_controller,omitempty"`
	CWND                 int               `json:"cwnd,omitempty"`
	// TimingJitterMinMS/MaxMS: если MaxMS > 0, перед каждой записью в
	// h2/TCP-сокет добавляется случайная задержка в [MinMS, MaxMS] мс —
	// разрушает статистику интервалов между исходящими пакетами (защита от
	// timing-фингерпринтинга DPI). ВЫКЛЮЧЕНО по умолчанию (0) — это прямой
	// trade-off с задержкой/пингом, включайте осознанно.
	TimingJitterMinMS int               `json:"timing_jitter_min_ms,omitempty"`
	TimingJitterMaxMS int               `json:"timing_jitter_max_ms,omitempty"`
	ClientRandomPrefix   string            `json:"client_random_prefix,omitempty"`
	// ClientRandomPrefixSecret/Len/Window — server side of the rotating-prefix
	// scheme; must match the client's OutboundTLSOptions values of the same
	// name. See option/tls.go for the full explanation. When
	// ClientRandomPrefixSecret is set, it takes priority over the static
	// ClientRandomPrefix for verification.
	ClientRandomPrefixSecret string `json:"client_random_prefix_secret,omitempty"`
	ClientRandomPrefixLen    int    `json:"client_random_prefix_len,omitempty"`
	ClientRandomPrefixWindow int    `json:"client_random_prefix_window,omitempty"`
	// FallbackServer — если задан, при неверном/отсутствующем client_random_prefix
	// (сканер, активный зонд) сырые байты проксируются на него, а не рвутся,
	// когда SNI из ClientHello извлечь не удалось (см. transport/trusttunnel/prefix_listener.go —
	// по умолчанию используется сам этот SNI, а FallbackServer лишь запасной вариант). Формат: "host:port".
	FallbackServer       string            `json:"fallback_server,omitempty"`
	AllowedSNI           []string          `json:"allowed_sni,omitempty"`
	UDPPaddingMin        *int              `json:"udp_padding_min,omitempty"`
	UDPPaddingMax        *int              `json:"udp_padding_max,omitempty"`
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
	Username             string                       `json:"username,omitempty"`
	Password             string                       `json:"password,omitempty"`
	Network              NetworkList                  `json:"network,omitempty"`
	HealthCheck          bool                         `json:"health_check,omitempty"`
	QUIC                 bool                         `json:"quic,omitempty"`
	CongestionController string                       `json:"congestion_controller,omitempty"`
	CWND                 int                          `json:"cwnd,omitempty"`
	TimingJitterMinMS    int                          `json:"timing_jitter_min_ms,omitempty"`
	TimingJitterMaxMS    int                          `json:"timing_jitter_max_ms,omitempty"`
	Multiplex            *TrustTunnelMultiplexOptions `json:"multiplex,omitempty"`
	UDPPaddingMin        *int                         `json:"udp_padding_min,omitempty"`
	UDPPaddingMax        *int                         `json:"udp_padding_max,omitempty"`
}
