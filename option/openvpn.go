package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type OpenVPNOutboundOptions struct {
	DialerOptions
	System         bool                             `json:"system,omitempty"`
	Name           string                           `json:"name,omitempty"`
	AllowedIPs     badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	Servers        []ServerOptions                  `json:"servers"`
	Proto          string                           `json:"proto,omitempty"`
	Cipher         string                           `json:"cipher,omitempty"`
	Auth           string                           `json:"auth,omitempty"`
	Username       string                           `json:"username,omitempty"`
	Password       string                           `json:"password,omitempty"`
	TLSCrypt       string                           `json:"tls_crypt,omitempty"`
	TLSCryptPath   string                           `json:"tls_crypt_path,omitempty"`
	TLSCryptV2     bool                             `json:"tls_crypt_v2,omitempty"`
	TLSAuth        string                           `json:"tls_auth,omitempty"`
	TLSAuthPath    string                           `json:"tls_auth_path,omitempty"`
	KeyDirection   int                              `json:"key_direction,omitempty"`
	ReconnectDelay badoption.Duration               `json:"reconnect_delay,omitempty"`
	PingInterval   badoption.Duration               `json:"ping_interval,omitempty"`
	OpenVPNOutboundTLSOptionsContainer
}

type OpenVPNTLSOptions struct {
	Certificate        string                     `json:"certificate,omitempty"`
	CertificatePath    string                     `json:"certificate_path,omitempty"`
	Key                string                     `json:"key,omitempty"`
	KeyPath            string                     `json:"key_path,omitempty"`
	CA                 string                     `json:"ca,omitempty"`
	CAPath             string                     `json:"ca_path,omitempty"`
	CipherSuites       badoption.Listable[string] `json:"cipher_suites,omitempty"`
	VerifyX509Name     string                     `json:"verify_x509_name,omitempty"`
	VerifyX509NameMode string                     `json:"verify_x509_name_mode,omitempty"`
	KernelTx           bool                       `json:"kernel_tx,omitempty"`
	KernelRx           bool                       `json:"kernel_rx,omitempty"`
}

type OpenVPNOutboundTLSOptionsContainer struct {
	TLS *OpenVPNTLSOptions `json:"tls,omitempty"`
}
