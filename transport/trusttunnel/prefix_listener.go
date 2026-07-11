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
type PrefixListener struct {
	net.Listener
	prefix       []byte
	mask         []byte
	fallback     string // static "host:port" fallback, used when SNI can't be extracted
	fallbackPort string // port to pair with the extracted SNI when dialing
	ownPort      string // our own listening port, used to detect self-loops
	logger       logger.ContextLogger
}

// NewPrefixListener parses the "hex" or "hex/mask_hex" format (same as
// outbound client_random_prefix) and returns a wrapping listener.
func NewPrefixListener(inner net.Listener, raw string, fallback string, log logger.ContextLogger) (net.Listener, error) {
	if raw == "" {
		return inner, nil
	}
	parts := strings.SplitN(raw, "/", 2)
	prefix, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("client_random_prefix: invalid hex: " + err.Error())
	}
	if len(prefix) == 0 || len(prefix) > 32 {
		return nil, errors.New("client_random_prefix: must be 1-32 bytes")
	}
	var mask []byte
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
		Listener:     inner,
		prefix:       prefix,
		mask:         mask,
		fallback:     fallback,
		fallbackPort: fallbackPort,
		ownPort:      ownPort,
		logger:       log,
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
		l.logger.Error("trusttunnel inbound: fallback target ", target, " resolves back to this server, refusing to avoid a proxy loop")
		return
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
