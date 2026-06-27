package option

type SnellOutboundOptions struct {
	DialerOptions
	ServerOptions
	PSK     string            `json:"psk"`
	Version int               `json:"version,omitempty"`
	Reuse   bool              `json:"reuse,omitempty"`
	Network NetworkList       `json:"network,omitempty"`
	Obfs    *SnellObfsOptions `json:"obfs,omitempty"`
}

type SnellInboundOptions struct {
	ListenOptions
	PSK     string            `json:"psk"`
	Version int               `json:"version,omitempty"`
	Network NetworkList       `json:"network,omitempty"`
	Obfs    *SnellObfsOptions `json:"obfs,omitempty"`
}

type SnellObfsOptions struct {
	Mode string `json:"mode,omitempty"`
	Host string `json:"host,omitempty"`
}
