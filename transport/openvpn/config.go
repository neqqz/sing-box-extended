package openvpn

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"

	CipherAES128GCM    = "AES-128-GCM"
	CipherAES192GCM    = "AES-192-GCM"
	CipherAES256GCM    = "AES-256-GCM"
	CipherAES128CBC    = "AES-128-CBC"
	CipherAES192CBC    = "AES-192-CBC"
	CipherAES256CBC    = "AES-256-CBC"
	CipherCHACHA20POLY = "CHACHA20-POLY1305"

	AuthMD5    = "MD5"
	AuthSHA1   = "SHA1"
	AuthSHA256 = "SHA256"
	AuthSHA384 = "SHA384"
	AuthSHA512 = "SHA512"
)

type ClientConfig struct {
	Proto        string
	Cipher       string
	Auth         string
	Username     string
	Password     string
	KeyDirection int

	TLSCrypt      []byte
	TLSCryptV2    bool
	TLSCryptKey   []byte
	TLSCryptV2WKc []byte
	TLSAuthKey    []byte
}

func (c *ClientConfig) Prepare() error {
	if c == nil {
		return errors.New("nil openvpn client config")
	}
	c.Proto = normalizeProto(c.Proto)
	c.Cipher = strings.ToUpper(strings.TrimSpace(c.Cipher))
	if c.Auth == "" {
		c.Auth = AuthSHA1
	}
	c.Auth = strings.ToUpper(strings.TrimSpace(c.Auth))
	if c.Proto != ProtoUDP && c.Proto != ProtoTCP {
		return fmt.Errorf("unsupported openvpn proto %q: only udp and tcp are supported", c.Proto)
	}
	if c.Cipher != "" && !isValidCipher(c.Cipher) {
		return fmt.Errorf("unsupported openvpn cipher %q", c.Cipher)
	}
	if !isValidAuth(c.Auth) {
		return fmt.Errorf("unsupported openvpn auth %q", c.Auth)
	}
	if c.TLSCryptV2 {
		kc, wkc, err := decodeTLSCryptV2Key(c.TLSCrypt)
		if err != nil {
			return fmt.Errorf("parse tls-crypt-v2 key: %w", err)
		}
		c.TLSCryptKey = kc
		c.TLSCryptV2WKc = wkc
		return nil
	}
	if len(strings.TrimSpace(string(c.TLSCrypt))) == 0 {
		return nil
	}
	key, err := decodeStaticKey(c.TLSCrypt)
	if err != nil {
		return fmt.Errorf("parse tls key: %w", err)
	}
	if c.KeyDirection >= 0 {
		c.TLSAuthKey = key
	} else {
		c.TLSCryptKey = key
	}
	return nil
}

func normalizeProto(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "", "udp", "udp4":
		return ProtoUDP
	case "tcp", "tcp-client", "tcp4", "tcp4-client":
		return ProtoTCP
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

func isValidCipher(cipher string) bool {
	switch cipher {
	case CipherAES128GCM, CipherAES192GCM, CipherAES256GCM,
		CipherAES128CBC, CipherAES192CBC, CipherAES256CBC,
		CipherCHACHA20POLY:
		return true
	}
	return false
}

func isValidAuth(auth string) bool {
	switch auth {
	case AuthMD5, AuthSHA1, AuthSHA256, AuthSHA384, AuthSHA512:
		return true
	}
	return false
}

func decodeStaticKey(block []byte) ([]byte, error) {
	var hexLines []string
	for _, raw := range strings.Split(string(block), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-----BEGIN OpenVPN Static key") || strings.HasPrefix(line, "-----END OpenVPN Static key") {
			continue
		}
		hexLines = append(hexLines, line)
	}
	encoded := strings.Join(hexLines, "")
	key, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(key) != 256 {
		return nil, fmt.Errorf("invalid static key length %d, expected 256 bytes", len(key))
	}
	return key, nil
}

func decodeTLSCryptV2Key(block []byte) (kc []byte, wkc []byte, err error) {
	data, err := decodePEM(block, "OpenVPN tls-crypt-v2 client key")
	if err != nil {
		return nil, nil, err
	}
	if len(data) < 256 {
		return nil, nil, fmt.Errorf("tls-crypt-v2 key too short: %d bytes", len(data))
	}
	return data[:256], data[256:], nil
}

func decodePEM(block []byte, expectedHeader string) ([]byte, error) {
	lines := strings.Split(string(block), "\n")
	var b64 strings.Builder
	inBlock := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "BEGIN") && strings.Contains(line, expectedHeader) {
			inBlock = true
			continue
		}
		if strings.Contains(line, "END") && strings.Contains(line, expectedHeader) {
			break
		}
		if inBlock {
			b64.WriteString(line)
		}
	}
	if b64.Len() == 0 {
		return nil, fmt.Errorf("no %s block found", expectedHeader)
	}
	return base64Decode(b64.String())
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
