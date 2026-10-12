package obfs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
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
	tlsPeekTimeout        = 5 * time.Second
	fallbackDialTimeout   = 5 * time.Second
	// maxClientHelloCapture bounds how much of the stream we buffer while
	// trying to extract SNI for the fallback path — real ClientHellos
	// (even with a full uTLS Chrome extension set) are well under this.
	maxClientHelloCapture = 8 << 10 // 8 KiB
	maxPendingChecks      = 1024
	// maxPendingChecksPerIP: one source (a scanner) must not fill matchSem and
	// starve everyone else. Kept generous because CGNAT shares one IP.
	maxPendingChecksPerIP = 64
	selfLoopLookupTimeout = 2 * time.Second
	maxFallbackRelays     = 256
	fallbackRelayLifetime = 60 * time.Second
)

// PrefixChecker validates the TLS ClientHello.Random prefix of a new TCP
// connection BEFORE it reaches the TLS layer. If the prefix doesn't match but
// a fallback is configured, well-formed ClientHello connections are relayed to
// the domain the client asked for (its own SNI) — steal-handshake-style — so an
// active probe sees what a real client of that domain would see.
//
// Check blocks (up to tlsPeekTimeout) and must be called from a per-connection
// goroutine, never from the accept loop: otherwise one stalled client delays
// every other accept.
type PrefixChecker struct {
	// provider: current set of checks (static prefixes or rotating secrets,
	// hot-reloadable — see common/tls/random_prefix_reload.go). A connection is
	// accepted if it matches ANY entry.
	provider     sboxtls.RandomPrefixProvider
	prefixLen    int
	replay       *sboxtls.ReplayCache
	fallback     string // static "host:port" fallback, used when SNI can't be extracted
	fallbackPort string // port to pair with the extracted SNI when dialing
	ownPort      string // our own listening port, used to detect self-loops
	logger       logger.ContextLogger
	matchSem     chan struct{} // bounds connections being peeked (pre-auth, unauthenticated)
	pendingMtx   sync.Mutex
	pendingByIP  map[netip.Addr]int
	relaySem     chan struct{} // bounds concurrent fallback relays
}

// NewPrefixChecker returns nil when provider is nil (check disabled).
func NewPrefixChecker(addr net.Addr, provider sboxtls.RandomPrefixProvider, prefixLen int, fallback string, fallbackSNIPort int, log logger.ContextLogger) *PrefixChecker {
	if provider == nil {
		return nil
	}
	ownPort := ""
	if addr != nil {
		if _, port, splitErr := net.SplitHostPort(addr.String()); splitErr == nil {
			ownPort = port
		}
	}
	return &PrefixChecker{
		provider:     provider,
		prefixLen:    prefixLen,
		replay:       sboxtls.NewReplayCache(),
		fallback:     fallback,
		fallbackPort: resolveFallbackPort(fallback, fallbackSNIPort),
		ownPort:      ownPort,
		logger:       log,
		matchSem:     make(chan struct{}, maxPendingChecks),
		pendingByIP:  make(map[netip.Addr]int),
		relaySem:     make(chan struct{}, maxFallbackRelays),
	}
}

// resolveFallbackPort picks the port that is paired with the SNI extracted from a
// probe's ClientHello when dialing its "real" site. An explicit sniPort wins;
// otherwise the port of the static fallback is used (the historical behaviour);
// otherwise 443. The explicit option exists so the static fallback can be a local
// site on another port while stolen SNIs still go to their own :443.
func resolveFallbackPort(fallback string, sniPort int) string {
	if sniPort > 0 {
		return strconv.Itoa(sniPort)
	}
	if fallback != "" {
		if _, port, err := net.SplitHostPort(fallback); err == nil && port != "" {
			return port
		}
	}
	return "443"
}

// acquirePending takes a global and a per-source slot for the pre-auth peek.
func (l *PrefixChecker) acquirePending(conn net.Conn) (netip.Addr, func(), bool) {
	var ip netip.Addr
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		ip = ap.Addr().Unmap()
	}
	if ip.IsValid() {
		l.pendingMtx.Lock()
		if l.pendingByIP[ip] >= maxPendingChecksPerIP {
			l.pendingMtx.Unlock()
			return ip, nil, false
		}
		l.pendingByIP[ip]++
		l.pendingMtx.Unlock()
	}
	select {
	case l.matchSem <- struct{}{}:
	default:
		l.releaseIP(ip)
		return ip, nil, false
	}
	return ip, func() {
		<-l.matchSem
		l.releaseIP(ip)
	}, true
}

func (l *PrefixChecker) releaseIP(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	l.pendingMtx.Lock()
	if l.pendingByIP[ip]--; l.pendingByIP[ip] <= 0 {
		delete(l.pendingByIP, ip)
	}
	l.pendingMtx.Unlock()
}

// peekResult is the outcome of inspecting the first bytes of a new connection.
type peekResult int

const (
	peekMatched        peekResult = iota // our client, valid marker
	peekNotClientHello                   // garbage / port scan, not even TLS
	peekMismatch                         // valid TLS ClientHello, wrong/missing marker
	peekReadFailed                       // couldn't read enough bytes in time
)

// Check returns the connection to hand to TLS (with peeked bytes replayed) and
// true on a match. Otherwise it consumes conn itself (drop, or relay to the
// fallback until it ends) and returns false.
func (l *PrefixChecker) Check(conn net.Conn) (net.Conn, bool) {
	_, release, ok := l.acquirePending(conn)
	if !ok {
		conn.Close()
		return nil, false
	}
	peeked, result := l.checkRandom(conn)
	release()
	switch result {
	case peekMatched:
		return &peekedConn{Conn: conn, buf: peeked}, true
	case peekMismatch:
		if l.fallback != "" {
			l.relayToFallback(conn, peeked)
			return nil, false
		}
	}
	conn.Close()
	return nil, false
}

// checkRandom peeks at the TLS ClientHello and verifies the Random prefix/mask.
// Returns the peeked bytes (always, when read succeeded) and the outcome.
//
// In secret (rotating) mode this reads the full ClientHello handshake
// message (possibly split across several TLS records by record_fragment),
// bounded by maxClientHelloCapture. Verification needs the key_share
// extension — see DeriveRotatingRandomPrefixBound.
//
// Without multi-record assembly a pure-X25519MLKEM768 ClientHello (~1.5KB+)
// that was split by record_fragment loses key_share in the first record and
// fails the rotating-prefix check even though the Random itself is correct.
func (l *PrefixChecker) checkRandom(conn net.Conn) ([]byte, peekResult) {
	if err := conn.SetReadDeadline(time.Now().Add(tlsPeekTimeout)); err != nil {
		return nil, peekReadFailed
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	// Assemble one logical ClientHello (handshake message) that may span
	// multiple consecutive Handshake TLS records. Returns a synthetic
	// single-record buffer so extractKeyShareData keeps working unchanged,
	// plus the raw bytes actually read from the wire (for peekedConn replay).
	wire, logical, ok := readFullClientHello(conn)
	if !ok {
		if len(wire) == 0 {
			return nil, peekReadFailed
		}
		if len(wire) >= 1 && wire[0] != 0x16 {
			l.logger.Debug("trusttunnel inbound: dropping non-ClientHello TCP connection")
			return wire, peekNotClientHello
		}
		l.logger.Debug("trusttunnel inbound: dropping truncated/non-ClientHello TLS stream")
		return wire, peekNotClientHello
	}
	if len(logical) < tlsClientRandomEnd || logical[5] != 0x01 {
		l.logger.Debug("trusttunnel inbound: dropping non-ClientHello TCP connection")
		return wire, peekNotClientHello
	}

	random := logical[tlsClientRandomOffset:tlsClientRandomEnd]

	set := l.provider.Current()
	if len(set.Secrets) > 0 {
		length := sboxtls.RandomPrefixLenOrDefault(l.prefixLen)
		bind, ok := extractKeyShareData(logical)
		if !ok {
			// A compliant TLS 1.3 ClientHello always carries key_share.
			// No key_share means either a non-1.3 client (we require 1.3 —
			// see min_version in the trusttunnel-in tls config) or an
			// attacker who copied a sniffed Random into a hand-built
			// ClientHello without one. Either way: treat like a wrong prefix.
			return wire, peekMismatch
		}
		// ANY configured secret; a repeated Random is a replay, so it is
		// treated like a wrong prefix (goes to fallback).
		if sboxtls.MatchRotatingRandomPrefixBound(set.Secrets, length, random, bind) && !l.replay.Seen(random) {
			return wire, peekMatched
		}
		return wire, peekMismatch
	}

	if sboxtls.MatchAnyRandomPrefix(set.Prefixes, random) {
		return wire, peekMatched
	}
	return wire, peekMismatch
}

// readFullClientHello reads one or more consecutive TLS Handshake records
// until a complete ClientHello handshake message is assembled.
//
// wire  — exact bytes consumed from the connection (for peekedConn replay).
// logical — synthetic single-record buffer (5-byte header + full handshake
//
//	message) suitable for extractKeyShareData / Random slicing.
//
// ok    — false on read error, non-handshake content, oversized payload, or
//
//	incomplete message within maxClientHelloCapture.
func readFullClientHello(conn net.Conn) (wire, logical []byte, ok bool) {
	var wireBuf bytes.Buffer
	var hsBuf bytes.Buffer // concatenated handshake-record payloads

	// Need at least: record hdr(5) + hs type(1) + hs len(3) + enough for Random.
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return wireBuf.Bytes(), nil, false
		}
		wireBuf.Write(header)

		if header[0] != 0x16 { // content_type = Handshake
			return wireBuf.Bytes(), nil, false
		}
		recordLen := int(header[3])<<8 | int(header[4])
		if recordLen <= 0 || wireBuf.Len()+recordLen > maxClientHelloCapture+5 {
			return wireBuf.Bytes(), nil, false
		}
		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return wireBuf.Bytes(), nil, false
		}
		wireBuf.Write(payload)
		hsBuf.Write(payload)

		// First record must start a ClientHello handshake message.
		if hsBuf.Len() < 4 {
			continue
		}
		hs := hsBuf.Bytes()
		if hs[0] != 0x01 { // handshake_type = ClientHello
			return wireBuf.Bytes(), nil, false
		}
		hsMsgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		// Total handshake message size including its 4-byte header.
		need := 4 + hsMsgLen
		if need > maxClientHelloCapture {
			return wireBuf.Bytes(), nil, false
		}
		if hsBuf.Len() < need {
			// Message continues in the next Handshake record.
			continue
		}
		if hsBuf.Len() > need {
			// Extra data after ClientHello in the same record stream —
			// shouldn't happen for a normal first flight; reject.
			return wireBuf.Bytes(), nil, false
		}

		// Build synthetic single-record view for existing parsers.
		msg := hs[:need]
		logical = make([]byte, 5+len(msg))
		logical[0] = 0x16
		logical[1] = 0x03
		logical[2] = 0x01
		logical[3] = byte(len(msg) >> 8)
		logical[4] = byte(len(msg))
		copy(logical[5:], msg)
		return wireBuf.Bytes(), logical, true
	}
}

// extractKeyShareData walks a raw ClientHello handshake message (buf,
// starting at the TLS record header) far enough to find the key_share
// extension (type 0x0033, RFC 8446 §4.2.8) and returns its body with the
// leading 2-byte client_shares_length stripped — i.e. the concatenated
// group+length+key_exchange entries exactly as they sit on the wire. This
// must byte-for-byte match serializeKeyShares in common/tls/utls_client.go,
// which builds the same bytes from the client's own parsed hello.KeyShares —
// that agreement is what DeriveRotatingRandomPrefixBound relies on.
//
// Returns ok=false on anything short, truncated, or missing the extension;
// callers must treat that as a mismatch, never fall back to trusting Random
// alone.
func extractKeyShareData(buf []byte) ([]byte, bool) {
	// buf[0:5] record header, buf[5:9] handshake header, buf[9:11]
	// client_version, buf[11:43] random (all already validated by the caller).
	if len(buf) < 43 {
		return nil, false
	}
	return extractKeyShareFromClientHelloBody(buf[9:])
}

// ExtractKeyShareFromHandshakeMessage is extractKeyShareData's counterpart
// for QUIC: buf there is the raw TLS Handshake message as delivered to a
// QUIC CRYPTO stream — i.e. starting at the 4-byte handshake header
// (1-byte type + 3-byte length), with no preceding 5-byte TLS record
// header, since QUIC doesn't use TLS record framing at all. Used by
// protocol/trusttunnel/inbound.go's QUIC path (see the ServerClientRandomVerify
// callback wired through github.com/neqqz/quic-go) to bind that path's
// rotating random-prefix check to key_share the same way the TCP/H2 path
// already does via extractKeyShareData above.
func ExtractKeyShareFromHandshakeMessage(buf []byte) ([]byte, bool) {
	// buf[0:4] handshake header, buf[4:6] client_version, buf[6:38] random.
	if len(buf) < 38 || buf[0] != 0x01 {
		return nil, false
	}
	return extractKeyShareFromClientHelloBody(buf[4:])
}

// extractKeyShareFromClientHelloBody does the actual walk, shared by both
// entry points above. body starts at client_version (2 bytes), followed by
// random (32 bytes), session_id, cipher_suites, compression_methods, and
// finally extensions — identical ClientHello body layout regardless of
// whether it arrived wrapped in a TLS record (TCP) or bare (QUIC CRYPTO).
func extractKeyShareFromClientHelloBody(body []byte) ([]byte, bool) {
	pos := 34 // 2 (client_version) + 32 (random)
	if pos+1 > len(body) {
		return nil, false
	}
	sessionIDLen := int(body[pos])
	pos++
	pos += sessionIDLen
	if pos+2 > len(body) {
		return nil, false
	}
	cipherSuitesLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(body) {
		return nil, false
	}
	compressionMethodsLen := int(body[pos])
	pos += 1 + compressionMethodsLen
	if pos+2 > len(body) {
		return nil, false
	}
	extensionsLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	end := pos + extensionsLen
	if end > len(body) {
		return nil, false
	}
	for pos+4 <= end {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extLen > end {
			return nil, false
		}
		if extType == 0x0033 { // key_share
			data := body[pos : pos+extLen]
			if len(data) < 2 {
				return nil, false
			}
			sharesLen := int(data[0])<<8 | int(data[1])
			if 2+sharesLen > len(data) {
				return nil, false
			}
			return data[2 : 2+sharesLen], true
		}
		pos += extLen
	}
	return nil, false
}

// relayToFallback figures out which real domain to impersonate for this probe
// (the SNI the prober itself sent, when we can extract it; otherwise the
// static fallback_server), dials it, replays the exact bytes seen so far, and
// splices the rest bidirectionally. Used for connections whose
// client_random_prefix didn't match — instead of a telltale reset, the
// prober gets the real, matching TLS response for the domain it asked for.
func (l *PrefixChecker) relayToFallback(conn net.Conn, peeked []byte) {
	defer conn.Close()

	select {
	case l.relaySem <- struct{}{}:
		defer func() { <-l.relaySem }()
	default:
		return
	}
	_ = conn.SetDeadline(time.Now().Add(fallbackRelayLifetime))

	captured, sni := l.captureClientHelloSNI(conn, peeked)

	target := l.fallback
	// The SNI is attacker-controlled: it may only lead to public addresses
	// (publicOnlyDialer), the operator-configured static fallback may be local.
	dialer := &net.Dialer{Timeout: fallbackDialTimeout}
	if sni != "" {
		target = net.JoinHostPort(sni, l.fallbackPort)
		dialer.Control = publicOnly
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
		dialer.Control = nil
	}

	upstream, err := dialer.Dial("tcp", target)
	if err != nil {
		l.logger.Debug("trusttunnel inbound: fallback dial to ", target, " failed: ", err)
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(fallbackRelayLifetime))

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

// publicOnly is a net.Dialer.Control that refuses non-public destinations;
// it runs after DNS resolution on the actual IP, so rebinding can't bypass it.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return errors.New("non-public fallback target")
	}
	return nil
}

// captureClientHelloSNI reads the rest of the ClientHello (bounded by
// maxClientHelloCapture and tlsPeekTimeout, already partly consumed into
// `already`) and extracts the SNI extension using the standard library's own
// TLS ClientHello parser via a read-only conn — the same technique sing-box
// already uses for TLS sniffing (see common/sniff/tls.go). Returns the full
// raw bytes seen (for replay to the fallback) and the SNI, which is empty if
// it couldn't be determined in time or wasn't present.
func (l *PrefixChecker) captureClientHelloSNI(conn net.Conn, already []byte) ([]byte, string) {
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
func (l *PrefixChecker) isSelfLoop(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || l.ownPort == "" || port != l.ownPort {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), selfLoopLookupTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
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
