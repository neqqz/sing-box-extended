package trusttunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	sboxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
)

const (
	// TLS record header(5) + Handshake header(4) + client_version(2) = 11 bytes offset to Random.
	// Random is 32 bytes: buf[11:43].
	tlsClientRandomOffset = 11
	tlsClientRandomEnd    = 43
	tlsPeekLen            = tlsClientRandomEnd // enough to verify + read full Random
	tlsPeekTimeout        = 5 * time.Second
	fallbackDialTimeout   = 5 * time.Second
	// maxClientHelloCapture bounds how much of the stream we buffer while
	// trying to extract SNI for the fallback path — real ClientHellos
	// (even with a full uTLS Chrome extension set) are well under this.
	maxClientHelloCapture = 8 << 10 // 8 KiB
)

// PrefixListener wraps a net.Listener to validate TLS ClientHello.Random prefix
// BEFORE passing the connection to the TLS layer. If the prefix doesn't match
// but a fallback server is configured, well-formed TLS ClientHello connections
// are transparently relayed to the domain the client actually asked for (its
// own SNI) — a steal-handshake-style fallback — so an active probe gets the
// same response a real client of that exact domain would see, instead of a
// dead giveaway "connection closed with zero bytes sent". If prefix is empty,
// the inner listener is returned unchanged.
//
// SECURITY: No IP whitelisting - any IP can connect, but only those sending
// a matching ClientHello.Random prefix will receive a response. Scanners
// without the prefix get immediate reset without TLS handshake attempt,
// providing reality-style HTTP fingerprinting without explicit IP bans.
type PrefixListener struct {
	net.Listener
	prefix       []byte
	mask         []byte
	// secret/prefixLen/windowSeconds: rotating-prefix mode (see
	// common/tls/random_prefix_rotation.go). When secret is non-empty, it
	// replaces prefix/mask above entirely — checkRandom derives the expected
	// bytes fresh for the current window (and its neighbors, for clock skew)
	// instead of comparing against a static value.
	secret        []byte
	prefixLen     int
	windowSeconds int
	fallback     string // static "host:port" fallback, used when SNI can't be extracted
	fallbackPort string // port to pair with the extracted SNI when dialing
	ownPort      string // our own listening port, used to detect self-loops
	logger       logger.ContextLogger
}

// NewPrefixListener parses the "hex" or "hex/mask_hex" format (same as
// outbound client_random_prefix) and returns a wrapping listener.
func NewPrefixListener(inner net.Listener, raw string, secretHex string, prefixLen int, windowSeconds int, fallback string, log logger.ContextLogger) (net.Listener, error) {
	if raw == "" && secretHex == "" {
		return inner, nil
	}
	if raw != "" && secretHex != "" {
		return nil, errors.New("client_random_prefix and client_random_prefix_secret are mutually exclusive; secret-based rotation replaces the static prefix entirely")
	}
	var prefix, mask, secret []byte
	if secretHex != "" {
		var err error
		secret, err = hex.DecodeString(secretHex)
		if err != nil {
			return nil, errors.New("client_random_prefix_secret: invalid hex: " + err.Error())
		}
		if len(secret) == 0 {
			return nil, errors.New("client_random_prefix_secret: must not be empty")
		}
	} else {
		parts := strings.SplitN(raw, "/", 2)
		var err error
		prefix, err = hex.DecodeString(parts[0])
		if err != nil {
			return nil, errors.New("client_random_prefix: invalid hex: " + err.Error())
		}
		if len(prefix) == 0 || len(prefix) > 32 {
			return nil, errors.New("client_random_prefix: must be 1-32 bytes")
		}
		if len(parts) == 2 {
			mask, err = hex.DecodeString(parts[1])
			if err != nil {
				return nil, errors.New("client_random_prefix: invalid mask hex: " + err.Error())
			}
			if len(mask) != len(prefix) {
				return nil, errors.New("client_random_prefix: mask length must equal prefix length")
			}
		} else {
			mask = bytes.Repeat([]byte{0xff}, len(prefix))
		}
	}
	fallbackPort := "443"
	if fallback != "" {
		if _, port, splitErr := net.SplitHostPort(fallback); splitErr == nil && port != "" {
			fallbackPort = port
		}
	}
	ownPort := ""
	if addr := inner.Addr(); addr != nil {
		if _, port, splitErr := net.SplitHostPort(addr.String()); splitErr == nil {
			ownPort = port
		}
	}
	return &PrefixListener{
		Listener:      inner,
		prefix:        prefix,
		mask:          mask,
		secret:        secret,
		prefixLen:     prefixLen,
		windowSeconds: windowSeconds,
		fallback:      fallback,
		fallbackPort:  fallbackPort,
		ownPort:       ownPort,
		logger:        log,
	}, nil
}

// peekResult is the outcome of inspecting the first bytes of a new connection.
type peekResult int

const (
	peekMatched       peekResult = iota // our client, valid marker
	peekNotClientHello                  // garbage / port scan, not even TLS
	peekMismatch                        // valid TLS ClientHello, wrong/missing marker
	peekReadFailed                      // couldn't read enough bytes in time
)

// Accept loops until it gets a connection that passes the prefix check,
// or until the underlying listener returns an error. Connections that fail
// the check are either dropped (garbage/timeout) or, if fallback is
// configured and the connection was a well-formed ClientHello, relayed to
// the fallback destination in a background goroutine.
//
// SECURITY: No IP whitelisting - any IP can connect, but only those sending
// a matching ClientHello.Random prefix will receive a response. Scanners
// without the prefix get immediate reset without TLS handshake attempt.
func (l *PrefixListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peeked, result := l.checkRandom(conn)
		switch result {
		case peekMatched:
			return &peekedConn{Conn: conn, buf: peeked}, nil
		case peekMismatch:
			if l.fallback != "" {
				go l.relayToFallback(conn, peeked)
				continue
			}
			l.logger.Debug("trusttunnel inbound: client_random_prefix mismatch, dropping")
			conn.Close()
		default: // peekNotClientHello, peekReadFailed
			conn.Close()
		}
	}
}

// checkRandom peeks at the TLS ClientHello and verifies the Random prefix/mask.
// Returns the peeked bytes (always, when read succeeded) and the outcome.
func (l *PrefixListener) checkRandom(conn net.Conn) ([]byte, peekResult) {
	if err := conn.SetReadDeadline(time.Now().Add(tlsPeekTimeout)); err != nil {
		return nil, peekReadFailed
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	buf := make([]byte, tlsPeekLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, peekReadFailed
	}

	// Minimal sanity: TLS content_type=0x16 (Handshake), handshake_type=0x01 (ClientHello).
	if buf[0] != 0x16 || buf[5] != 0x01 {
		l.logger.Debug("trusttunnel inbound: dropping non-ClientHello TCP connection")
		return buf, peekNotClientHello
	}

	random := buf[tlsClientRandomOffset:tlsClientRandomEnd]

	if len(l.secret) > 0 {
		// Rotating mode: derive the expected prefix for the current window
		// and its immediate neighbors (network delay / clock skew between
		// client and server can put a connection one window off in either
		// direction) and accept a match against any of them.
		length := sboxtls.RandomPrefixLenOrDefault(l.prefixLen)
		now := sboxtls.CurrentRandomPrefixWindow(time.Now().Unix(), l.windowSeconds)
		for _, window := range [3]int64{now - 1, now, now + 1} {
			expected := sboxtls.DeriveRotatingRandomPrefix(l.secret, length, window)
			if bytes.Equal(random[:length], expected) {
				return buf, peekMatched
			}
		}
		return buf, peekMismatch
	}

	for i, b := range l.prefix {
		if random[i]&l.mask[i] != b&l.mask[i] {
			return buf, peekMismatch
		}
	}
	return buf, peekMatched
}

// relayToFallback figures out which real domain to impersonate for this probe
// (the SNI the prober itself sent, when we can extract it; otherwise the
// static fallback_server), dials it, replays the exact bytes seen so far, and
// splices the rest bidirectionally. Used for connections whose
// client_random_prefix didn't match — instead of a telltale reset, the
// prober gets the real, matching TLS response for the domain it asked for.
// CRITICAL: This function only relays if authentication was verified on the
// underlying connection (before this relay path is ever reached). The auth
// check happens in service.go:158 (ServeHTTP) which validates
// Proxy-Authorization before calling into the transport layer.
func (l *PrefixListener) relayToFallback(conn net.Conn, peeked []byte) {
	defer conn.Close()

	captured, sni := l.captureClientHelloSNI(conn, peeked)

	target := l.fallback
	if sni != "" {
		target = net.JoinHostPort(sni, l.fallbackPort)
	}
	if target == "" {
		return
	}
	if l.isSelfLoop(target) {
		// The SNI the prober sent resolves back to us — this legitimately
		// happens for cert_domain, whose DNS A record has to point here
		// for HTTP-01 ACME validation. Aborting right after ClientHello
		// (as before) produces a distinctive "instant close, no TLS
		// response" signature that differs from the graceful full-handshake
		// relay every other SNI gets — itself a fingerprint an attacker
		// correlating Certificate Transparency logs with server IPs could
		// use to single this server out. Instead, degrade to the static
		// fallback_server (a real, unrelated site) so this probe still gets
		// an indistinguishable relay, same as any other SNI would.
		if l.fallback == "" || l.isSelfLoop(l.fallback) {
			l.logger.Error("trusttunnel inbound: fallback target ", target, " resolves back to this server and no usable fallback_server is configured; closing without a response")
			return
		}
		l.logger.Debug("trusttunnel inbound: fallback target ", target, " resolves back to this server; using static fallback_server instead")
		target = l.fallback
	}

	upstream, err := net.DialTimeout("tcp", target, fallbackDialTimeout)
	if err != nil {
		l.logger.Debug("trusttunnel inbound: fallback dial to ", target, " failed: ", err)
		return
	}
	defer upstream.Close()

	if len(captured) > 0 {
		if _, err := upstream.Write(captured); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, conn)
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, upstream)
		if c, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
}

// captureClientHelloSNI reads the rest of the ClientHello (bounded by
// maxClientHelloCapture and tlsPeekTimeout, already partly consumed into
// `already`) and extracts the SNI extension using the standard library's own
// TLS ClientHello parser via a read-only conn — the same technique sing-box
// already uses for TLS sniffing (see common/sniff/tls.go). Returns the full
// raw bytes seen (for replay to the fallback) and the SNI, which is empty if
// it couldn't be determined in time or wasn't present.
func (l *PrefixListener) captureClientHelloSNI(conn net.Conn, already []byte) ([]byte, string) {
	var captured bytes.Buffer
	captured.Write(already)

	remaining := int64(maxClientHelloCapture - len(already))
	if remaining < 0 {
		remaining = 0
	}
	tee := io.TeeReader(io.LimitReader(conn, remaining), &captured)
	reader := io.MultiReader(bytes.NewReader(already), tee)

	ctx, cancel := context.WithTimeout(context.Background(), tlsPeekTimeout)
	defer cancel()

	var sni string
	_ = tls.Server(bufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, nil
		},
	}).HandshakeContext(ctx)

	return captured.Bytes(), sni
}

// isSelfLoop reports whether target resolves to this same machine on the
// same port we're listening on — dialing it would just re-enter our own
// Accept() loop with the same unmatched ClientHello, looping forever and
// exhausting sockets/goroutines. Checked by port first (cheap), then by
// resolving the host and comparing against this machine's own interface
// addresses.
func (l *PrefixListener) isSelfLoop(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || l.ownPort == "" || port != l.ownPort {
		return false
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return false
	}
	localAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IP.IsLoopback() {
			return true
		}
		for _, localAddr := range localAddrs {
			ipNet, ok := localAddr.(*net.IPNet)
			if ok && ipNet.IP.Equal(ip.IP) {
				return true
			}
		}
	}
	return false
}

// peekedConn replays the bytes we already read back to subsequent Read calls,
// ensuring the TLS layer sees the complete, unmodified stream.
type peekedConn struct {
	net.Conn
	buf []byte
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}
