package clash

import (
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type HTTPOptions struct {
	Method  string               `yaml:"method,omitempty"`
	Path    []string             `yaml:"path,omitempty"`
	Headers badoption.HTTPHeader `yaml:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty"`
}

type WSOptions struct {
	Path                string            `yaml:"path,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty"`
	MaxEarlyData        int               `yaml:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade    bool              `yaml:"v2ray-http-upgrade,omitempty"`
}

type MuxOptions struct {
	Enabled        bool           `yaml:"enabled,omitempty"`
	Protocol       string         `yaml:"protocol,omitempty"`
	MaxConnections int            `yaml:"max-connections,omitempty"`
	MinStreams     int            `yaml:"min-streams,omitempty"`
	MaxStreams     int            `yaml:"max-streams,omitempty"`
	Padding        bool           `yaml:"padding,omitempty"`
	BrutalOpts     *BrutalOptions `yaml:"brutal-opts,omitempty"`
}

func (s *MuxOptions) Build() *option.OutboundMultiplexOptions {
	if s == nil {
		return nil
	}
	return &option.OutboundMultiplexOptions{
		Enabled:        s.Enabled,
		Protocol:       s.Protocol,
		MaxConnections: s.MaxConnections,
		MinStreams:     s.MinStreams,
		MaxStreams:     s.MaxStreams,
		Padding:        s.Padding,
		Brutal:         s.BrutalOpts.Build(),
	}
}

type BrutalOptions struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Up      string `yaml:"up,omitempty"`
	Down    string `yaml:"down,omitempty"`
}

func (b *BrutalOptions) Build() *option.BrutalOptions {
	if b == nil {
		return nil
	}
	return &option.BrutalOptions{
		Enabled:  b.Enabled,
		UpMbps:   clashSpeedToIntMbps(b.Up),
		DownMbps: clashSpeedToIntMbps(b.Down),
	}
}

type RealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

func (r *RealityOptions) Build() *option.OutboundRealityOptions {
	if r == nil {
		return nil
	}
	return &option.OutboundRealityOptions{
		Enabled:   true,
		PublicKey: r.PublicKey,
		ShortID:   r.ShortID,
	}
}

type ECHOptions struct {
	Enable bool   `yaml:"enable,omitempty"`
	Config string `yaml:"config,omitempty"`
}

func (e *ECHOptions) Build() *option.OutboundECHOptions {
	if e == nil {
		return nil
	}
	list, err := base64.StdEncoding.DecodeString(e.Config)
	if err != nil {
		return nil
	}
	return &option.OutboundECHOptions{
		Enabled: e.Enable,
		Config:  trimStringArray(strings.Split(string(list), "\n")),
	}
}

type TLSOptions struct {
	TLS               bool            `yaml:"tls,omitempty"`
	SNI               string          `yaml:"sni,omitempty"`
	SkipCertVerify    bool            `yaml:"skip-cert-verify,omitempty"`
	ALPN              []string        `yaml:"alpn,omitempty"`
	ClientFingerprint string          `yaml:"client-fingerprint,omitempty"`
	CustomCA          string          `yaml:"ca,omitempty"`
	CustomCAString    string          `yaml:"ca-str,omitempty"`
	Certificate       string          `yaml:"certificate,omitempty"`
	PrivateKey        string          `yaml:"private-key,omitempty"`
	ECHOpts           *ECHOptions     `yaml:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions `yaml:"reality-opts,omitempty"`
}

func (t *TLSOptions) Build() *option.OutboundTLSOptions {
	if t == nil {
		return nil
	}
	options := &option.OutboundTLSOptions{
		Enabled:         t.TLS,
		ServerName:      t.SNI,
		Insecure:        t.SkipCertVerify,
		ALPN:            t.ALPN,
		UTLS:            clashClientFingerprint(t.ClientFingerprint),
		Certificate:     trimStringArray(strings.Split(t.CustomCAString, "\n")),
		CertificatePath: t.CustomCA,
		ECH:             t.ECHOpts.Build(),
		Reality:         t.RealityOpts.Build(),
	}
	if strings.HasPrefix(t.Certificate, "-----BEGIN ") {
		options.ClientCertificate = trimStringArray(strings.Split(t.Certificate, "\n"))
	} else {
		options.ClientCertificatePath = t.Certificate
	}
	if strings.HasPrefix(t.PrivateKey, "-----BEGIN ") {
		options.ClientKey = trimStringArray(strings.Split(t.PrivateKey, "\n"))
	} else {
		options.ClientKeyPath = t.PrivateKey
	}
	return options
}

type DialerOptions struct {
	TFO         bool   `yaml:"tfo,omitempty"`
	MPTCP       bool   `yaml:"mptcp,omitempty"`
	Interface   string `yaml:"interface-name,omitempty"`
	RoutingMark int    `yaml:"routing-mark,omitempty"`
	DialerProxy string `yaml:"dialer-proxy,omitempty"`
}

func (b *DialerOptions) Build() option.DialerOptions {
	return option.DialerOptions{
		Detour: b.DialerProxy,
		AbstractDialerOptions: option.AbstractDialerOptions{
			BindInterface: b.Interface,
			TCPFastOpen:   b.TFO,
			TCPMultiPath:  b.MPTCP,
			RoutingMark:   option.FwMark(b.RoutingMark),
		},
	}
}

type ServerOptions struct {
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
}

func (s *ServerOptions) Build() option.ServerOptions {
	return option.ServerOptions{
		Server:     s.Server,
		ServerPort: uint16(s.Port),
	}
}
