//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

type UTLSClientConfig struct {
	ctx                   context.Context
	config                *utls.Config
	id                    utls.ClientHelloID
	fragment              bool
	fragmentFallbackDelay time.Duration
	recordFragment        bool
	// certDomain: если задан, cert верифицируется по этому домену вместо server_name.
	// SNI в ClientHello остаётся = config.ServerName.
	certDomain string
	// clientRandomPrefix/clientRandomMask: байты для патча TLS ClientHello.Random
	clientRandomPrefix []byte
	clientRandomMask   []byte
}

func (c *UTLSClientConfig) ServerName() string {
	return c.config.ServerName
}

func (c *UTLSClientConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *UTLSClientConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *UTLSClientConfig) SetNextProtos(nextProto []string) {
	if len(nextProto) == 1 && nextProto[0] == http2.NextProtoTLS {
		nextProto = append(nextProto, "http/1.1")
	}
	c.config.NextProtos = nextProto
}

func (c *UTLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for uTLS")
}

func (c *UTLSClientConfig) Client(conn net.Conn) (Conn, error) {
	if c.recordFragment {
		conn = tf.NewConn(conn, c.ctx, c.fragment, c.recordFragment, c.fragmentFallbackDelay)
	}
	cfg := c.config.Clone()
	// Если certDomain задан — отключаем стандартную проверку hostname и делаем свою
	if c.certDomain != "" {
		cfg.InsecureSkipVerify = true
		certDomain := c.certDomain
		rootCAs := cfg.RootCAs
		timeFn := cfg.Time
		cfg.VerifyConnection = func(state utls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return E.New("tls: no peer certificates")
			}
			opts := x509.VerifyOptions{
				DNSName:       certDomain,
				Roots:         rootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if timeFn != nil {
				opts.CurrentTime = timeFn()
			}
			_, err := state.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	return &utlsALPNWrapper{
		utlsConnWrapper:    utlsConnWrapper{utls.UClient(conn, cfg, c.id)},
		nextProtocols:      cfg.NextProtos,
		clientRandomPrefix: c.clientRandomPrefix,
		clientRandomMask:   c.clientRandomMask,
	}, nil
}

func (c *UTLSClientConfig) SetSessionIDGenerator(generator func(clientHello []byte, sessionID []byte) error) {
	c.config.SessionIDGenerator = generator
}

func (c *UTLSClientConfig) Clone() Config {
	return &UTLSClientConfig{
		ctx:                   c.ctx,
		config:                c.config.Clone(),
		id:                    c.id,
		fragment:              c.fragment,
		fragmentFallbackDelay: c.fragmentFallbackDelay,
		recordFragment:        c.recordFragment,
		certDomain:            c.certDomain,
		clientRandomPrefix:    c.clientRandomPrefix,
		clientRandomMask:      c.clientRandomMask,
	}
}

func (c *UTLSClientConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *UTLSClientConfig) SetECHConfigList(EncryptedClientHelloConfigList []byte) {
	c.config.EncryptedClientHelloConfigList = EncryptedClientHelloConfigList
}

type utlsConnWrapper struct {
	*utls.UConn
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *utlsConnWrapper) Upstream() any {
	return c.UConn
}

func (c *utlsConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *utlsConnWrapper) WriterReplaceable() bool {
	return true
}

type utlsALPNWrapper struct {
	utlsConnWrapper
	nextProtocols      []string
	clientRandomPrefix []byte
	clientRandomMask   []byte
}

func (c *utlsALPNWrapper) HandshakeContext(ctx context.Context) error {
	if len(c.nextProtocols) > 0 || len(c.clientRandomPrefix) > 0 {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
		// Патч ALPN extension
		if len(c.nextProtocols) > 0 {
			for _, extension := range c.Extensions {
				if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
					alpnExtension.AlpnProtocols = c.nextProtocols
					err = c.BuildHandshakeState()
					if err != nil {
						return err
					}
					break
				}
			}
		}
		// Патч ClientHello.Random — применяем prefix с маской
		// Логика идентична TrustTunnel C++: result[i] = (prefix[i] & mask[i]) | (random[i] & ~mask[i])
		if len(c.clientRandomPrefix) > 0 {
			hello := c.HandshakeState.Hello
			if hello != nil && len(hello.Random) == 32 {
				prefixLen := len(c.clientRandomPrefix)
				if prefixLen > 32 {
					prefixLen = 32
				}
				for i := 0; i < prefixLen; i++ {
					var mask byte = 0xff
					if i < len(c.clientRandomMask) {
						mask = c.clientRandomMask[i]
					}
					hello.Random[i] = (c.clientRandomPrefix[i] & mask) | (hello.Random[i] & ^mask)
				}
				// Sync Raw buffer
				if len(hello.Raw) >= 38 {
					copy(hello.Raw[6:38], hello.Random)
				}

			}
		}
	}
	return c.UConn.HandshakeContext(ctx)
}

func NewUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure {
		return nil, E.New("missing server_name or insecure=true")
	}

	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if !options.DisableSNI {
		tlsConfig.ServerName = serverName
	}
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("disable_sni is unsupported in reality")
		}
		tlsConfig.InsecureServerNameToVerify = serverName
	}
	if len(options.CertificatePublicKeySHA256) > 0 {
		if len(options.Certificate) > 0 || options.CertificatePath != "" {
			return nil, E.New("certificate_public_key_sha256 is conflict with certificate or certificate_path")
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPublicKeySHA256(options.CertificatePublicKeySHA256, rawCerts, tlsConfig.Time)
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := os.ReadFile(options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate:\n\n", certificate)
		}
		tlsConfig.RootCAs = certPool
	}
	var clientCertificate []byte
	if len(options.ClientCertificate) > 0 {
		clientCertificate = []byte(strings.Join(options.ClientCertificate, "\n"))
	} else if options.ClientCertificatePath != "" {
		content, err := os.ReadFile(options.ClientCertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read client certificate")
		}
		clientCertificate = content
	}
	var clientKey []byte
	if len(options.ClientKey) > 0 {
		clientKey = []byte(strings.Join(options.ClientKey, "\n"))
	} else if options.ClientKeyPath != "" {
		content, err := os.ReadFile(options.ClientKeyPath)
		if err != nil {
			return nil, E.Cause(err, "read client key")
		}
		clientKey = content
	}
	if len(clientCertificate) > 0 && len(clientKey) > 0 {
		keyPair, err := utls.X509KeyPair(clientCertificate, clientKey)
		if err != nil {
			return nil, E.Cause(err, "parse client x509 key pair")
		}
		tlsConfig.Certificates = []utls.Certificate{keyPair}
	} else if len(clientCertificate) > 0 || len(clientKey) > 0 {
		return nil, E.New("client certificate and client key must be provided together")
	}
	id, err := uTLSClientHelloID(options.UTLS.Fingerprint)
	if err != nil {
		return nil, err
	}
	// Парсим client_random_prefix: формат "hex" или "hex/mask_hex" (как в TrustTunnel)
	var clientRandomPrefix, clientRandomMask []byte
	if options.ClientRandomPrefix != "" {
		parts := strings.SplitN(options.ClientRandomPrefix, "/", 2)
		clientRandomPrefix, err = hex.DecodeString(parts[0])
		if err != nil {
			return nil, E.Cause(err, "parse client_random_prefix: invalid hex")
		}
		if len(clientRandomPrefix) > 32 {
			return nil, E.New("client_random_prefix: too long (max 32 bytes)")
		}
		if len(parts) == 2 {
			clientRandomMask, err = hex.DecodeString(parts[1])
			if err != nil {
				return nil, E.Cause(err, "parse client_random_prefix mask: invalid hex")
			}
			if len(clientRandomMask) != len(clientRandomPrefix) {
				return nil, E.New("client_random_prefix: mask length must equal prefix length")
			}
		}
	}
	var config Config = &UTLSClientConfig{
		ctx:                   ctx,
		config:                &tlsConfig,
		id:                    id,
		fragment:              options.Fragment,
		fragmentFallbackDelay: time.Duration(options.FragmentFallbackDelay),
		recordFragment:        options.RecordFragment,
		certDomain:            options.CertDomain,
		clientRandomPrefix:    clientRandomPrefix,
		clientRandomMask:      clientRandomMask,
	}
	if options.ECH != nil && options.ECH.Enabled {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("Reality is conflict with ECH")
		}
		config, err = parseECHClientConfig(ctx, config.(ECHCapableConfig), options)
		if err != nil {
			return nil, err
		}
	}
	if (options.KernelRx || options.KernelTx) && !common.PtrValueOrDefault(options.Reality).Enabled {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

var (
	randomFingerprint     utls.ClientHelloID
	randomizedFingerprint utls.ClientHelloID
)

func init() {
	modernFingerprints := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomizedFingerprint = utls.HelloRandomized
	randomizedFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedFingerprint.Weights = &weights
}

func uTLSClientHelloID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk":
		fallthrough
	case "chrome", "":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random":
		return randomFingerprint, nil
	case "randomized":
		return randomizedFingerprint, nil
	default:
		return utls.ClientHelloID{}, E.New("unknown uTLS fingerprint: ", name)
	}
}
