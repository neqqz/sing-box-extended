package option

import "github.com/sagernet/sing/common/json/badoption"

type SSHInboundOptions struct {
	ListenOptions
	Users         []SSHUser                  `json:"users,omitempty"`
	HostKey       badoption.Listable[string] `json:"host_key,omitempty"`
	HostKeyPath   badoption.Listable[string] `json:"host_key_path,omitempty"`
	ServerVersion string                     `json:"server_version,omitempty"`
	MaxAuthTries  int                        `json:"max_auth_tries,omitempty"`
	Fallback      *SSHFallbackServerOptions  `json:"fallback,omitempty"`
}

type SSHFallbackServerOptions struct {
	DialerOptions
	ServerOptions
	CA                     *SSHCAOptions              `json:"ca,omitempty"`
	IssueCA                *SSHCAOptions              `json:"issue_ca,omitempty"`
	HostKey                badoption.Listable[string] `json:"host_key,omitempty"`
	HostKeyPath            badoption.Listable[string] `json:"host_key_path,omitempty"`
	HostKeyAlgorithms      badoption.Listable[string] `json:"host_key_algorithms,omitempty"`
	ClientVersion          string                     `json:"client_version,omitempty"`
}

type SSHCAOptions struct {
	PrivateKey           badoption.Listable[string] `json:"private_key,omitempty"`
	PrivateKeyPath       string                     `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string                     `json:"private_key_passphrase,omitempty"`
}

type SSHUser struct {
	Name           string                     `json:"name,omitempty"`
	Password       string                     `json:"password,omitempty"`
	AuthorizedKeys badoption.Listable[string] `json:"authorized_keys,omitempty"`
}

type SSHOutboundOptions struct {
	DialerOptions
	ServerOptions
	User                 string                     `json:"user,omitempty"`
	Password             string                     `json:"password,omitempty"`
	PrivateKey           badoption.Listable[string] `json:"private_key,omitempty"`
	PrivateKeyPath       string                     `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string                     `json:"private_key_passphrase,omitempty"`
	HostKey              badoption.Listable[string] `json:"host_key,omitempty"`
	HostKeyAlgorithms    badoption.Listable[string] `json:"host_key_algorithms,omitempty"`
	ClientVersion        string                     `json:"client_version,omitempty"`
	Cipher               badoption.Listable[string] `json:"cipher,omitempty"`
	MAC                  badoption.Listable[string] `json:"mac,omitempty"`
	KexAlgorithm         badoption.Listable[string] `json:"kex_algorithm,omitempty"`
}
