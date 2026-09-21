package option

import "github.com/sagernet/sing/common/json/badoption"

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
	PacketPadding *TrustTunnelPaddingOptions `json:"packet_padding,omitempty"`
	// ClientRandomPrefix — строка или массив строк ("hex" или "hex/mask_hex").
	// Сервер принимает соединение, если ClientHello.Random начинается с ЛЮБОГО
	// из перечисленных префиксов.
	ClientRandomPrefix badoption.Listable[string] `json:"client_random_prefix,omitempty"`
	// ClientRandomPrefixSecret/Len/Window — server side of the rotating-prefix
	// scheme; must match the client's OutboundTLSOptions values of the same
	// name. See option/tls.go for the full explanation.
	// ClientRandomPrefixSecret is a string or an array: the server accepts a
	// client whose secret matches ANY entry (e.g. one secret per user). When
	// set, it takes priority over the static ClientRandomPrefix for verification.
	ClientRandomPrefixSecret badoption.Listable[string] `json:"client_random_prefix_secret,omitempty"`
	ClientRandomPrefixLen    int                        `json:"client_random_prefix_len,omitempty"`
	ClientRandomPrefixWindow int                        `json:"client_random_prefix_window,omitempty"`
	// ClientRandomPrefixFile / ClientRandomPrefixSecretFile — файлы со списками
	// префиксов ("hex" или "hex/mask_hex") и секретов (hex), по одной записи на
	// строку; пустые строки игнорируются, всё после '#' — комментарий (удобно
	// подписывать, чей секрет). Записи из файла объединяются с client_random_prefix /
	// client_random_prefix_secret. Файлы перечитываются на лету (раз в ~5 с):
	// новые соединения проверяются по обновлённому списку без перезапуска.
	// Невалидное или пустое содержимое отклоняется — остаётся прежний список.
	// Len и Window на лету не меняются.
	ClientRandomPrefixFile       string `json:"client_random_prefix_file,omitempty"`
	ClientRandomPrefixSecretFile string `json:"client_random_prefix_secret_file,omitempty"`
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
