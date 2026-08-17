package option

// TrustTunnelPaddingOptions задаёт диапазон [Min, Max] байт случайного
// паддинга. Используется для data_padding (h2 DATA-фреймы), packet_padding
// (QUIC-пакеты) и udp_padding (полезная нагрузка UDP-relay протокола) — см.
// пояснения у соответствующих полей ниже. Отсутствует (nil) по умолчанию —
// выключено.
type TrustTunnelPaddingOptions struct {
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
}

// TrustTunnelTimingOptions задаёт джиттер по времени: если MaxMS > 0, перед
// каждой записью в сокет добавляется случайная задержка в [MinMS, MaxMS] мс —
// разрушает статистику интервалов между исходящими пакетами (защита от
// timing-фингерпринтинга DPI). Отсутствует (nil) по умолчанию — прямой
// trade-off с задержкой/пингом, включайте осознанно.
type TrustTunnelTimingOptions struct {
	MinMS int `json:"min_ms,omitempty"`
	MaxMS int `json:"max_ms,omitempty"`
}

type TrustTunnelInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users                []TrustTunnelUser        `json:"users,omitempty"`
	Network              NetworkList               `json:"network,omitempty"`
	CongestionController string                    `json:"congestion_controller,omitempty"`
	CWND                 int                       `json:"cwnd,omitempty"`
	Timing               *TrustTunnelTimingOptions `json:"timing,omitempty"`
	// DataPadding: рандомный PADDED-паддинг на h2 DATA-фреймы (байты). У
	// PADDED-флага HTTP/2 однобайтовое поле длины паддинга (RFC 7540 §6.1),
	// поэтому Max > 255 не имеет смысла на этом пути.
	DataPadding *TrustTunnelPaddingOptions `json:"data_padding,omitempty"`
	// PacketPadding: то же самое, но для обычных QUIC-пакетов (см.
	// Config.ExtraPacketPaddingMin/Max в форке quic-go). Не путать с
	// UDPPadding ниже — тот про полезную нагрузку UDP-relay протокола
	// поверх туннеля, этот — про размер самих QUIC-пакетов на проводе.
	PacketPadding      *TrustTunnelPaddingOptions `json:"packet_padding,omitempty"`
	ClientRandomPrefix string                     `json:"client_random_prefix,omitempty"`
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
	FallbackServer string   `json:"fallback_server,omitempty"`
	AllowedSNI     []string `json:"allowed_sni,omitempty"`
	// RateLimitAuthAttempts — макс. неудачных попыток аутентификации с одного IP
	// в течение RateLimitAuthWindow. Защита от брутфорса DPI.
	RateLimitAuthAttempts int `json:"rate_limit_auth_attempts,omitempty"`
	// RateLimitAuthWindow — окно в секундах для rate limiting auth.
	RateLimitAuthWindow int `json:"rate_limit_auth_window,omitempty"`
	// UDPPadding — паддинг полезной нагрузки UDP-relay протокола; тот же
	// формат [Min, Max], что и у DataPadding/PacketPadding выше.
	UDPPadding *TrustTunnelPaddingOptions `json:"udp_padding,omitempty"`
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
	Timing               *TrustTunnelTimingOptions    `json:"timing,omitempty"`
	// See the matching fields on TrustTunnelInboundOptions for the format
	// and rationale.
	DataPadding   *TrustTunnelPaddingOptions   `json:"data_padding,omitempty"`
	PacketPadding *TrustTunnelPaddingOptions   `json:"packet_padding,omitempty"`
	Multiplex     *TrustTunnelMultiplexOptions `json:"multiplex,omitempty"`
	UDPPadding    *TrustTunnelPaddingOptions   `json:"udp_padding,omitempty"`
}
