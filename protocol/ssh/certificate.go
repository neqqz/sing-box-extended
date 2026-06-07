package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/crypto/ssh"
)

func parseCAKey(options *option.SSHCAOptions) (ssh.Signer, error) {
	var keyData []byte
	var err error
	if len(options.PrivateKey) > 0 {
		keyData = []byte(strings.Join(options.PrivateKey, "\n"))
	} else if options.PrivateKeyPath != "" {
		keyData, err = os.ReadFile(os.ExpandEnv(options.PrivateKeyPath))
		if err != nil {
			return nil, E.Cause(err, "read CA private key")
		}
	} else {
		return nil, E.New("missing CA private key")
	}
	if options.PrivateKeyPassphrase == "" {
		return ssh.ParsePrivateKey(keyData)
	}
	return ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(options.PrivateKeyPassphrase))
}

func verifyCertificate(signer ssh.Signer, metadata ssh.ConnMetadata, key ssh.PublicKey) bool {
	if signer == nil {
		return false
	}
	certificate, ok := key.(*ssh.Certificate)
	if !ok {
		return false
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), signer.PublicKey().Marshal())
		},
	}
	if !checker.IsUserAuthority(certificate.SignatureKey) {
		return false
	}
	return checker.CheckCert(metadata.User(), certificate) == nil
}

func issueCertificate(signer ssh.Signer, user string) (ssh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ssh.NewSignerFromSigner(privateKey)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	certificate := &ssh.Certificate{
		Key:             ephemeral.PublicKey(),
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           user,
		ValidPrincipals: []string{user},
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(5 * time.Minute).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-port-forwarding":  "",
				"permit-agent-forwarding": "",
				"permit-X11-forwarding":   "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := certificate.SignCert(rand.Reader, signer); err != nil {
		return nil, E.Cause(err, "sign certificate")
	}
	certSigner, err := ssh.NewCertSigner(certificate, ephemeral)
	if err != nil {
		return nil, E.Cause(err, "create certificate signer")
	}
	return certSigner, nil
}
