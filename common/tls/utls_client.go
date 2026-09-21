//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
)

type UTLSClientConfig struct {
	ctx                   context.Context
	config                *utls.Config
	serverName            string
	disableSNI            bool
	verifyServerName      bool
	handshakeTimeout      time.Duration
	id                    utls.ClientHelloID
	fragment              bool
	fragmentFallbackDelay time.Duration
	recordFragment        bool
	// certDomain: если задан, cert верифицируется по этому домену вместо server_name.
	// SNI в ClientHello остаётся = config.ServerName.
	certDomain string
	// clientRandomPrefixes: статичные префиксы для патча TLS ClientHello.Random;
	// на каждом соединении выбирается случайный из списка. Используются, только
	// если clientRandomPrefixSecret не задан.
	clientRandomPrefixes []RandomPrefix
	// clientRandomPrefixSecret: если задан, prefix для ClientHello.Random
	// вычисляется заново в Client() на каждое соединение (см. DeriveRotatingRandomPrefix)
	// вместо использования статичных clientRandomPrefixes выше.
	clientRandomPrefixSecrets [][]byte
	clientRandomPrefixLen     int
	clientRandomPrefixWindow  int
	spoof                     string
	spoofMethod               tlsspoof.Method
}

func (c *UTLSClientConfig) ServerName() string {
	return c.serverName
}

func (c *UTLSClientConfig) SetServerName(serverName string) {
	c.serverName = serverName
	if c.disableSNI {
		c.config.ServerName = ""
		if c.verifyServerName {
			c.config.InsecureServerNameToVerify = serverName
		} else {
			c.config.InsecureServerNameToVerify = ""
		}
		return
	}
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

func (c *UTLSClientConfig) HandshakeTimeout() time.Duration {
	return c.handshakeTimeout
}

func (c *UTLSClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.handshakeTimeout = timeout
}

func (c *UTLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for uTLS")
}

func (c *UTLSClientConfig) Client(conn net.Conn) (Conn, error) {
	if c.fragment || c.recordFragment {
		conn = tf.NewConn(conn, c.ctx, c.fragment, c.recordFragment, c.fragmentFallbackDelay)
	}
	conn, err := applyTLSSpoof(conn, c.spoof, c.spoofMethod)
	if err != nil {
		return nil, err
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
	// Ротация: раньше значение вычислялось прямо здесь, один раз на вызов
	// Client(). Так больше нельзя — привязка к key_share (см.
	// DeriveRotatingRandomPrefixBound) требует уже сгенерированного
	// hello.KeyShares, а он появляется только после BuildHandshakeState(),
	// которого на этом этапе ещё не было. Поэтому для secret-режима сами
	// байты префикса теперь считаются в HandshakeContext ниже; сюда просто
	// прокидываем secret/len/window как есть.
	uconn, err := c.buildUConn(conn, cfg)
	if err != nil {
		return nil, err
	}
	return &utlsALPNWrapper{
		utlsConnWrapper:           utlsConnWrapper{uconn},
		nextProtocols:             cfg.NextProtos,
		clientRandomPrefixes:      c.clientRandomPrefixes,
		clientRandomPrefixSecrets: c.clientRandomPrefixSecrets,
		clientRandomPrefixLen:     c.clientRandomPrefixLen,
		clientRandomPrefixWindow:  c.clientRandomPrefixWindow,
	}, nil
}

// injectCurvePreferences патчит уже готовый ClientHelloSpec конкретного
// fingerprint'а (firefox/safari/edge/360/qq/ios/android/...), заменяя его
// список групп в supported_groups/key_share на explicit curve_preferences
// пользователя — ровно тот же список, что для QUIC уже понимает
// stdTLSConfig() ниже (общий "curve_preferences" в tls-блоке, а не
// какая-то отдельная опция под utls).
//
// Ведущий GREASE (если он был в оригинальном спеке) сохраняется только
// когда в prefs есть хотя бы одна классическая группа. Для чистого
// X25519MLKEM768 GREASE намеренно НЕ добавляется: иначе wire-формат
// key_share (после re-GREASE в ApplyPreset) и serializeKeyShares(hello.KeyShares)
// легко расходятся на 1 байт Data у GREASE-записи, и
// client_random_prefix_secret перестаёт сходиться даже без fragment.
//
// Реальную PQ-криптографию (генерацию ML-KEM-ключа и склейку с X25519)
// делает сам uTLS внутри (*UConn).ApplyPreset() для KeyShare с пустым Data.
//
// Возвращает false, если у спека вообще нет KeyShareExtension/
// SupportedCurvesExtension (TLS 1.2-only паррот — заменять там нечего).
func injectCurvePreferences(spec *utls.ClientHelloSpec, prefs []utls.CurveID) bool {
	var hasCurves, hasKeyShare bool
	keepGREASE := !prefsOnlyPostQuantum(prefs)
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			hasCurves = true
			if keepGREASE {
				e.Curves = withLeadingGREASE(e.Curves, prefs)
			} else {
				e.Curves = append([]utls.CurveID(nil), prefs...)
			}
		case *utls.KeyShareExtension:
			hasKeyShare = true
			shares := make([]utls.KeyShare, len(prefs))
			for i, curve := range prefs {
				shares[i] = utls.KeyShare{Group: curve}
			}
			if keepGREASE {
				e.KeyShares = withLeadingGREASEKeyShare(e.KeyShares, shares)
			} else {
				e.KeyShares = shares
			}
		}
	}
	return hasCurves && hasKeyShare
}

// prefsOnlyPostQuantum — true, если в списке только гибридные/PQ группы
// (сейчас достаточно X25519MLKEM768). Для таких списков GREASE в key_share
// вреден для bind'а rotating prefix.
func prefsOnlyPostQuantum(prefs []utls.CurveID) bool {
	if len(prefs) == 0 {
		return false
	}
	for _, c := range prefs {
		if c != utls.X25519MLKEM768 {
			return false
		}
	}
	return true
}

// withLeadingGREASE/withLeadingGREASEKeyShare сохраняют ведущий
// GREASE-плейсхолдер оригинального списка (если он там был) перед новым
// списком групп/key share.
func withLeadingGREASE(original []utls.CurveID, prefs []utls.CurveID) []utls.CurveID {
	out := make([]utls.CurveID, 0, len(prefs)+1)
	if len(original) > 0 && original[0] == utls.CurveID(utls.GREASE_PLACEHOLDER) {
		out = append(out, utls.CurveID(utls.GREASE_PLACEHOLDER))
	}
	return append(out, prefs...)
}

func withLeadingGREASEKeyShare(original []utls.KeyShare, prefs []utls.KeyShare) []utls.KeyShare {
	out := make([]utls.KeyShare, 0, len(prefs)+1)
	if len(original) > 0 && original[0].Group == utls.CurveID(utls.GREASE_PLACEHOLDER) {
		out = append(out, utls.KeyShare{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}})
	}
	return append(out, prefs...)
}

// buildUConn создаёт *utls.UConn для соединения. Если curve_preferences в
// конфиге не задан (дефолт) — поведение как раньше, один в один по
// выбранному fingerprint'у. Если задан — берём НЕЗАВИСИМУЮ копию
// ClientHelloSpec для c.id заново на КАЖДОЕ соединение (не кэшируем и не
// переиспользуем один объект между коннектами: (*UConn).ApplyPreset
// мутирует срезы Extensions на месте — например, при регрейсинге
// GREASE-плейсхолдеров — так что общий спек на несколько параллельных
// коннектов был бы гонкой по данным, это прямо оговорено в комментарии к
// ApplyPreset в самом uTLS), патчим её списком групп из
// c.config.CurvePreferences и уже патченную скармливаем через
// HelloCustom+ApplyPreset.
func (c *UTLSClientConfig) buildUConn(conn net.Conn, cfg *utls.Config) (*utls.UConn, error) {
	if len(cfg.CurvePreferences) == 0 {
		return utls.UClient(conn, cfg, c.id), nil
	}
	spec, err := utls.UTLSIdToSpec(c.id)
	if err != nil {
		// custom/неизвестный ID (сюда не должны попадать валидные
		// fingerprint'ы из uTLSClientHelloID) — работаем как раньше.
		return utls.UClient(conn, cfg, c.id), nil
	}
	if !injectCurvePreferences(&spec, cfg.CurvePreferences) {
		// TLS 1.2-only спек — заменять нечего.
		return utls.UClient(conn, cfg, c.id), nil
	}
	uconn := utls.UClient(conn, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, E.Cause(err, "apply curve_preferences to client hello spec")
	}
	return uconn, nil
}

// serializeKeyShares восстанавливает wire-формат key_share extension entries
// (group + key_exchange с 2-байтовой длиной, RFC 8446 §4.2.8) из уже
// сгенерированного uTLS'ом hello.KeyShares, в том же порядке, в котором они
// уйдут на провод. Это ровно то же самое, что сервер потом достаёт из сырых
// байт реального ClientHello сам (см. extractKeyShareData в
// transport/trusttunnel/prefix_listener.go) — обе стороны должны получить
// побайтово одинаковый результат, иначе DeriveRotatingRandomPrefixBound не
// сойдётся.
func serializeKeyShares(shares []utls.KeyShare) []byte {
	var buf bytes.Buffer
	for _, ks := range shares {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], uint16(ks.Group))
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(ks.Data)))
		buf.Write(hdr[:])
		buf.Write(ks.Data)
	}
	return buf.Bytes()
}

func (c *UTLSClientConfig) SetSessionIDGenerator(generator func(clientHello []byte, sessionID []byte) error) {
	c.config.SessionIDGenerator = generator
}

func (c *UTLSClientConfig) Clone() Config {
	cloned := &UTLSClientConfig{
		ctx:                       c.ctx,
		config:                    c.config.Clone(),
		serverName:                c.serverName,
		disableSNI:                c.disableSNI,
		verifyServerName:          c.verifyServerName,
		handshakeTimeout:          c.handshakeTimeout,
		id:                        c.id,
		fragment:                  c.fragment,
		fragmentFallbackDelay:     c.fragmentFallbackDelay,
		recordFragment:            c.recordFragment,
		certDomain:                c.certDomain,
		clientRandomPrefixes:      c.clientRandomPrefixes,
		clientRandomPrefixSecrets: c.clientRandomPrefixSecrets,
		clientRandomPrefixLen:     c.clientRandomPrefixLen,
		clientRandomPrefixWindow:  c.clientRandomPrefixWindow,
		spoof:                     c.spoof,
		spoofMethod:               c.spoofMethod,
	}
	cloned.SetServerName(cloned.serverName)
	return cloned
}

func (c *UTLSClientConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *UTLSClientConfig) SetECHConfigList(EncryptedClientHelloConfigList []byte) {
	c.config.EncryptedClientHelloConfigList = EncryptedClientHelloConfigList
}

// stdTLSConfig строит crypto/tls.Config для QUIC (utls не используется напрямую в QUIC).
func (c *UTLSClientConfig) stdTLSConfig() *tls.Config {
	cfg := &tls.Config{
		ServerName:         c.config.ServerName,
		RootCAs:            c.config.RootCAs,
		NextProtos:         c.config.NextProtos,
		InsecureSkipVerify: c.config.InsecureSkipVerify,
		MinVersion:         c.config.MinVersion,
		MaxVersion:         c.config.MaxVersion,
		// CurvePreferences: если пользователь задал явно — уважаем его выбор.
		// Иначе современный дефолт Go (с X25519MLKEM768).
		// Раньше PQ вырезали из-за размера ClientHello (~1479 байт) и
		// проблем с TUN MTU 1280 на Android. Вырезание отключено.
		CurvePreferences: func() []tls.CurveID {
			if len(c.config.CurvePreferences) > 0 {
				out := make([]tls.CurveID, len(c.config.CurvePreferences))
				for i, id := range c.config.CurvePreferences {
					out[i] = tls.CurveID(id)
				}
				return out
			}
			return []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
		}(),
	}
	if c.certDomain != "" {
		cfg.InsecureSkipVerify = true
		certDomain := c.certDomain
		rootCAs := c.config.RootCAs
		timeFn := c.config.Time
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
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
	return cfg
}

// quicConfigWithRandom возвращает копию quic.Config с ClientRandomPrefix/Mask
// (или, для ChromeParrot при ротации, с ClientRandomPrefixBind — см. ниже)
// и, если выбранный uTLS-фингерпринт — chrome, включает нативный
// sagernet'овский ChromeParrot (transport parameters/idle timeout/packet size
// под Chrome — заменяет наше старое cloned.ClientHelloID, которого в
// quic.Config больше нет; ChromeParrot по сути делает то же самое точнее,
// на уровне самого QUIC, а не только TLS).
func (c *UTLSClientConfig) quicConfigWithRandom(cfg *quic.Config) *quic.Config {
	chromeParrot := c.id == utls.HelloChrome_Auto
	var prefix, mask []byte
	if len(c.clientRandomPrefixes) > 0 {
		// Новый случайный выбор на КАЖДЫЙ dial (метод зовётся заново на каждое подключение).
		picked := PickRandomPrefix(c.clientRandomPrefixes)
		prefix, mask = picked.Prefix, picked.Mask
	}
	var bind func(keyShare []byte) []byte
	if len(c.clientRandomPrefixSecrets) > 0 {
		// Секрет выбирается (если их несколько) на КАЖДЫЙ dial.
		secret := PickRandomPrefixSecret(c.clientRandomPrefixSecrets)
		// Ротация: пересчитываем заново на каждый вызов (= каждый реальный
		// dial). Именно поэтому важно, ГДЕ этот метод вызывается — см.
		// CreateTransport ниже, замыкание Dial должно звать этот метод
		// заново на каждое подключение, а не переиспользовать значение,
		// посчитанное один раз при первом вызове.
		length := RandomPrefixLenOrDefault(c.clientRandomPrefixLen)
		window := CurrentRandomPrefixWindow(time.Now().Unix(), c.clientRandomPrefixWindow)
		if chromeParrot {
			// ChromeParrot идёт через uTLS (см. newUTLSQUICClient в форке
			// github.com/neqqz/quic-go), который даёт доступ к
			// hello.KeyShares ДО отправки ClientHello — тем же способом,
			// что и TCP-путь выше (utlsALPNWrapper.HandshakeContext),
			// можно привязать префикс к key_share этого конкретного
			// handshake вместо одного значения на все клиенты в течение
			// окна. Обычный (не-ChromeParrot) QUIC-клиент идёт через
			// голый crypto/tls, у которого такого хука нет (см.
			// ClientRandomPrefixBind в quic-go/interface.go и
			// DeriveRotatingRandomPrefix в random_prefix_rotation.go) —
			// для него остаётся небиндящий вариант в блоке else ниже.
			bind = func(keyShare []byte) []byte {
				return DeriveRotatingRandomPrefixBound(secret, length, window, keyShare)
			}
			prefix, mask = nil, nil
		} else {
			prefix = DeriveRotatingRandomPrefix(secret, length, window)
			mask = nil
		}
	}
	if len(prefix) == 0 && bind == nil && !chromeParrot {
		return cfg
	}
	cloned := cfg.Clone()
	if len(prefix) > 0 {
		cloned.ClientRandomPrefix = prefix
		cloned.ClientRandomMask = mask
	}
	if bind != nil {
		cloned.ClientRandomPrefixBind = bind
	}
	cloned.ChromeParrot = chromeParrot
	return cloned
}

func (c *UTLSClientConfig) Dial(ctx context.Context, conn net.PacketConn, addr net.Addr, quicConfig *quic.Config) (*quic.Conn, error) {
	return quic.Dial(ctx, conn, addr, c.stdTLSConfig(), c.quicConfigWithRandom(quicConfig))
}

func (c *UTLSClientConfig) DialEarly(ctx context.Context, conn net.PacketConn, addr net.Addr, quicConfig *quic.Config) (*quic.Conn, error) {
	return quic.DialEarly(ctx, conn, addr, c.stdTLSConfig(), c.quicConfigWithRandom(quicConfig))
}

func (c *UTLSClientConfig) CreateTransport(conn net.PacketConn, quicConnPtr **quic.Conn, serverAddr M.Socksaddr, quicConfig *quic.Config) http.RoundTripper {
	return &http3.Transport{
		TLSClientConfig: c.stdTLSConfig(),
		QUICConfig:      c.quicConfigWithRandom(quicConfig),
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, dialCfg *quic.Config) (*quic.Conn, error) {
			// Пересчитываем заново на КАЖДЫЙ вызов этого замыкания — оно
			// зовётся http3.Transport'ом на каждое новое QUIC-соединение
			// за время жизни транспорта (реконнекты, доливка до
			// multiplex.max_connections), а не один раз. Если бы мы взяли
			// значение из внешней области видимости (посчитанное один раз
			// при вызове CreateTransport), все соединения этого транспорта
			// получили бы один и тот же "случайный" префикс навсегда —
			// именно то, от чего мы уходим.
			return quic.DialEarly(ctx, conn, serverAddr.UDPAddr(), tlsCfg, c.quicConfigWithRandom(quicConfig))
		},
	}
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
	nextProtocols        []string
	clientRandomPrefixes []RandomPrefix
	// Ротация (см. common/tls/random_prefix_rotation.go). Когда
	// clientRandomPrefixSecret задан, clientRandomPrefixes выше
	// игнорируются, а реальные байты префикса считаются ниже, в
	// HandshakeContext, уже после BuildHandshakeState() — привязанными к
	// hello.KeyShares этого конкретного соединения, а не к одному и тому же
	// значению для всех клиентов в течение окна (как было раньше).
	clientRandomPrefixSecrets [][]byte
	clientRandomPrefixLen     int
	clientRandomPrefixWindow  int
}

func (c *utlsALPNWrapper) HandshakeContext(ctx context.Context) error {
	needsBuild := len(c.nextProtocols) > 0 || len(c.clientRandomPrefixes) > 0 || len(c.clientRandomPrefixSecrets) > 0
	if needsBuild {
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

		var randomPrefix, randomMask []byte
		if len(c.clientRandomPrefixes) > 0 {
			// Новый случайный выбор на КАЖДОЕ соединение.
			picked := PickRandomPrefix(c.clientRandomPrefixes)
			randomPrefix, randomMask = picked.Prefix, picked.Mask
		}
		if len(c.clientRandomPrefixSecrets) > 0 {
			// hello.KeyShares уже сгенерирован BuildHandshakeState() выше —
			// вот почему это нельзя было посчитать заранее в Client().
			var bind []byte
			if hello := c.HandshakeState.Hello; hello != nil {
				bind = serializeKeyShares(hello.KeyShares)
			}
			length := RandomPrefixLenOrDefault(c.clientRandomPrefixLen)
			window := CurrentRandomPrefixWindow(time.Now().Unix(), c.clientRandomPrefixWindow)
			randomPrefix = DeriveRotatingRandomPrefixBound(PickRandomPrefixSecret(c.clientRandomPrefixSecrets), length, window, bind)
			randomMask = nil
		}

		// Патч ClientHello.Random — применяем prefix с маской (in-place)
		if len(randomPrefix) > 0 {
			hello := c.HandshakeState.Hello
			if hello != nil && len(hello.Random) == 32 {
				prefixLen := len(randomPrefix)
				if prefixLen > 32 {
					prefixLen = 32
				}
				for i := 0; i < prefixLen; i++ {
					var mask byte = 0xff
					if i < len(randomMask) {
						mask = randomMask[i]
					}
					hello.Random[i] = (randomPrefix[i] & mask) | (hello.Random[i] & ^mask)
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
	return newUTLSClient(ctx, logger, serverAddress, options, false)
}

func newUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure && !allowEmptyServerName {
		return nil, errMissingServerName
	}

	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("disable_sni is unsupported in reality")
		}
	}
	if len(options.CertificatePublicKeySHA256) > 0 {
		if len(options.Certificate) > 0 || options.CertificatePath != "" {
			return nil, E.New("certificate_public_key_sha256 is conflict with certificate or certificate_path")
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return VerifyPublicKeySHA256(options.CertificatePublicKeySHA256, rawCerts)
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
	// Раньше curve_preferences читался только в stdTLSConfig() (QUIC) —
	// для uTLS-пути (H2) tlsConfig.CurvePreferences никогда не заполнялся,
	// так что явное указание curve_preferences в конфиге фактически не
	// действовало на H2 вообще. Здесь — тот же цикл, что в std_client.go
	// для обычного TLS-движка, чтобы оба транспорта читали одно и то же
	// поле одинаково.
	for _, curve := range options.CurvePreferences {
		tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, utls.CurveID(curve))
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
		content, err := filemanager.ReadFile(ctx, options.CertificatePath)
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
		content, err := filemanager.ReadFile(ctx, options.ClientCertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read client certificate")
		}
		clientCertificate = content
	}
	var clientKey []byte
	if len(options.ClientKey) > 0 {
		clientKey = []byte(strings.Join(options.ClientKey, "\n"))
	} else if options.ClientKeyPath != "" {
		content, err := filemanager.ReadFile(ctx, options.ClientKeyPath)
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
	var handshakeTimeout time.Duration
	if options.HandshakeTimeout > 0 {
		handshakeTimeout = options.HandshakeTimeout.Build()
	} else {
		handshakeTimeout = C.TCPTimeout
	}
	spoof, spoofMethod, err := parseTLSSpoofOptions(serverName, options)
	if err != nil {
		return nil, err
	}
	id, err := uTLSClientHelloID(options.UTLS.Fingerprint)
	if err != nil {
		return nil, err
	}
	// Парсим client_random_prefix: строка или массив строк, формат каждой
	// записи "hex" или "hex/mask_hex".
	clientRandomPrefixes, err := ParseRandomPrefixes(options.ClientRandomPrefix)
	if err != nil {
		return nil, err
	}
	clientRandomPrefixSecrets, err := ParseRandomPrefixSecrets(options.ClientRandomPrefixSecret)
	if err != nil {
		return nil, err
	}
	if len(clientRandomPrefixSecrets) > 0 && len(clientRandomPrefixes) > 0 {
		return nil, E.New("client_random_prefix and client_random_prefix_secret are mutually exclusive; secret-based rotation replaces the static prefix entirely")
	}
	var config Config = &UTLSClientConfig{
		ctx:                       ctx,
		config:                    &tlsConfig,
		serverName:                serverName,
		disableSNI:                options.DisableSNI,
		verifyServerName:          options.DisableSNI && !options.Insecure,
		handshakeTimeout:          handshakeTimeout,
		id:                        id,
		fragment:                  options.Fragment,
		fragmentFallbackDelay:     time.Duration(options.FragmentFallbackDelay),
		recordFragment:            options.RecordFragment,
		certDomain:                options.CertDomain,
		clientRandomPrefixes:      clientRandomPrefixes,
		clientRandomPrefixSecrets: clientRandomPrefixSecrets,
		clientRandomPrefixLen:     options.ClientRandomPrefixLen,
		clientRandomPrefixWindow:  options.ClientRandomPrefixWindow,
		spoof:                     spoof,
		spoofMethod:               spoofMethod,
	}
	config.SetServerName(serverName)
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
	case "chrome", "":
		return utls.HelloChrome_Auto, nil
	// Раньше все пять вариантов ниже падали через fallthrough на
	// HelloChrome_Auto (так же, как апстрим сделал начиная с sing-box
	// 1.10.0, см. docs/configuration/shared/tls.md — "Removed since
	// sing-box 1.10.0"). В этом форке возвращаем реальные привязки:
	// HelloChrome_Auto = HelloChrome_133 уже сам по себе PQ (X25519MLKEM768
	// первым в KeyShare), так что "chrome_pq"/"chrome_pq_psk" тут — это
	// более старый черновой Kyber768Draft00 (Chrome 115), а не альтернатива
	// "включить PQ вместо не-PQ".
	case "chrome_psk":
		return utls.HelloChrome_100_PSK, nil
	case "chrome_psk_shuffle":
		return utls.HelloChrome_112_PSK_Shuf, nil
	case "chrome_padding_psk_shuffle":
		return utls.HelloChrome_114_Padding_PSK_Shuf, nil
	case "chrome_pq":
		return utls.HelloChrome_115_PQ, nil
	case "chrome_pq_psk":
		return utls.HelloChrome_115_PQ_PSK, nil
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
