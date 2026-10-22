package trusttunnel

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/sagernet/sing/common/network"
	randv2 "math/rand/v2"
)

const (
	UDPMagicAddress           = "_udp2"
	HealthCheckMagicAddress   = "_check"
	DefaultHealthCheckTimeout = 7 * time.Second
	DefaultSessionTimeout     = 30 * time.Second
	DefaultKeepAlivePeriod    = 10 * time.Second

	AuthBearerPrefix = "Bearer "
	TokenVersion     = byte(1)
	AuthMaxSkewSec   = 90
	tokenHeaderLen   = 1 + 8 + 8 + 2
)

func buildTokenAuth(username, password, target string) string {
	now := uint64(time.Now().Unix())
	userBytes := []byte(username)
	userLen := len(userBytes)
	totalLen := tokenHeaderLen + userLen + sha256.Size
	buf := make([]byte, totalLen)

	buf[0] = TokenVersion
	binary.BigEndian.PutUint64(buf[1:9], now)
	_, _ = crand.Read(buf[9:17])
	binary.BigEndian.PutUint16(buf[17:19], uint16(userLen))
	copy(buf[19:19+userLen], userBytes)

	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(buf[:19+userLen])
	mac.Write([]byte(target))
	mac.Sum(buf[:19+userLen])

	return AuthBearerPrefix + base64.RawURLEncoding.EncodeToString(buf)
}

func parseTokenAuth(auth string) (user string, timestamp int64, nonce [8]byte, sig []byte, ok bool) {
	if len(auth) < len(AuthBearerPrefix) || !strings.EqualFold(auth[:len(AuthBearerPrefix)], AuthBearerPrefix) {
		return "", 0, [8]byte{}, nil, false
	}
	tokenStr := strings.TrimSpace(auth[len(AuthBearerPrefix):])
	buf, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil || len(buf) < tokenHeaderLen+sha256.Size {
		return "", 0, [8]byte{}, nil, false
	}
	if buf[0] != TokenVersion {
		return "", 0, [8]byte{}, nil, false
	}
	ts := int64(binary.BigEndian.Uint64(buf[1:9]))
	copy(nonce[:], buf[9:17])
	userLen := int(binary.BigEndian.Uint16(buf[17:19]))
	if len(buf) != tokenHeaderLen+userLen+sha256.Size {
		return "", 0, [8]byte{}, nil, false
	}
	user = string(buf[19 : 19+userLen])
	sig = buf[19+userLen:]
	ok = true
	return
}

type authReplayCache struct {
	mu   sync.Mutex
	seen map[[8]byte]int64
}

func newAuthReplayCache() *authReplayCache {
	return &authReplayCache{seen: make(map[[8]byte]int64)}
}

func (c *authReplayCache) checkAndAdd(nonce [8]byte, now int64, ttl int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[nonce]; ok && now < exp {
		return false
	}
	if len(c.seen) > 10000 {
		for k, exp := range c.seen {
			if now >= exp {
				delete(c.seen, k)
			}
		}
	}
	c.seen[nonce] = now + ttl
	return true
}

func parse16BytesIP(b [16]byte) netip.Addr {
	// Standard IPv4-mapped IPv6: ::ffff:a.b.c.d
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
		b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
		b[8] == 0 && b[9] == 0 && b[10] == 0xff && b[11] == 0xff {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
		b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
		b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 &&
		!(b[12] == 0 && b[13] == 0 && b[14] == 0 && (b[15] == 0 || b[15] == 1)) {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return netip.AddrFrom16(b)
}

func buildPaddingIP(addr netip.Addr) (buffer [16]byte) {
	if addr.Is6() {
		return addr.As16()
	}
	ipv4 := addr.As4()
	copy(buffer[12:16], ipv4[:])
	return buffer
}

var (
	udpPaddingPool        [65536]byte
	udpPaddingPoolCounter atomic.Uint32
)

func init() {
	_, _ = crand.Read(udpPaddingPool[:])
}

// randomUDPPaddingLength возвращает случайную длину паддинга в [min, max]
// (в байтах).
func randomUDPPaddingLength(min, max int) int {
	if max <= 0 || min < 0 || max < min {
		return 0
	}
	if max == min {
		return min
	}
	return min + randv2.IntN(max-min+1)
}

// randomUDPPadding возвращает n байт случайного паддинга без аллокаций в куче.
func randomUDPPadding(n int) []byte {
	if n <= 0 {
		return nil
	}
	if n >= len(udpPaddingPool) {
		return udpPaddingPool[:]
	}
	offset := randv2.IntN(len(udpPaddingPool) - n + 1)
	if udpPaddingPoolCounter.Add(1)&0x3ff == 0 {
		var fresh [256]byte
		if _, err := crand.Read(fresh[:]); err == nil {
			refreshOffset := randv2.IntN(len(udpPaddingPool) - len(fresh) + 1)
			copy(udpPaddingPool[refreshOffset:], fresh[:])
		}
	}
	return udpPaddingPool[offset : offset+n]
}

type httpConn struct {
	writer     io.Writer
	flusher    http.Flusher
	body       io.ReadCloser
	setupOnce  sync.Once
	created    chan struct{}
	createErr  error
	cancelFn   func()
	closeFn    func()
	remoteAddr net.Addr
	localAddr  net.Addr
	done       chan struct{}
	doneOnce   sync.Once
	closed     bool
	mtx        sync.Mutex
}

func (h *httpConn) setup(body io.ReadCloser, err error) {
	h.setupOnce.Do(func() {
		h.body = body
		h.createErr = err
		close(h.created)
	})
	if h.createErr != nil && body != nil {
		_ = body.Close()
	}
}

func (h *httpConn) waitCreated() error {
	<-h.created
	h.mtx.Lock()
	closed := h.closed
	h.mtx.Unlock()
	if closed {
		return net.ErrClosed
	}
	if h.createErr != nil {
		return h.createErr
	}
	if h.body == nil {
		return net.ErrClosed
	}
	return nil
}

func (h *httpConn) Close() error {
	// Record ErrClosed before cancelling, so the request goroutine cannot win
	// with context.Canceled. Cancel before locking: a Write blocked on peer flow
	// control holds h.mtx, and only aborting the request unblocks it.
	h.setup(nil, net.ErrClosed)
	if h.cancelFn != nil {
		h.cancelFn()
	}
	var body io.ReadCloser
	h.mtx.Lock()
	if h.closed {
		h.mtx.Unlock()
		return nil
	}
	h.closed = true
	body = h.body
	h.mtx.Unlock()
	if closer, ok := h.writer.(io.Closer); ok {
		_ = closer.Close()
	}
	if body != nil {
		_ = body.Close()
	}
	if h.closeFn != nil {
		h.closeFn()
	}
	if h.done != nil {
		h.doneOnce.Do(func() {
			close(h.done)
		})
	}
	return nil
}

func (h *httpConn) writeFlush(p []byte) (n int, err error) {
	err = h.writeChunks(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeChunks writes chunks to the underlying writer under h.mtx, so it
// can't race with Close() setting h.closed / closing the writer, and
// flushes once at the end. Use this (rather than writing to h.writer
// directly) for anything that issues more than one Write per logical
// packet, so the writes stay atomic with respect to concurrent writers.
func (h *httpConn) writeChunks(chunks ...[]byte) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	for _, chunk := range chunks {
		if _, err := h.writer.Write(chunk); err != nil {
			return err
		}
	}
	if h.flusher != nil {
		h.flusher.Flush()
	}
	return nil
}

func (h *httpConn) RemoteAddr() net.Addr {
	if h.remoteAddr != nil {
		return h.remoteAddr
	}
	return &net.TCPAddr{}
}

func (h *httpConn) LocalAddr() net.Addr {
	if h.localAddr != nil {
		return h.localAddr
	}
	return &net.TCPAddr{}
}

// Deadlines are not supported: returning os.ErrInvalid makes sing-box wrap the
// conn with deadline.NewConn (NeedAdditionalReadDeadline), which emulates them
// without closing the stream from a timer.
func (h *httpConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (h *httpConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (h *httpConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }

func (h *httpConn) NeedAdditionalReadDeadline() bool { return true }

var (
	_ net.Conn      = (*tcpConn)(nil)
	_ N.WriteCloser = (*tcpConn)(nil)
)

type tcpConn struct{ httpConn }

func (t *tcpConn) Read(b []byte) (n int, err error) {
	if err = t.waitCreated(); err != nil {
		return 0, err
	}
	t.mtx.Lock()
	if t.closed || t.body == nil {
		t.mtx.Unlock()
		return 0, net.ErrClosed
	}
	body := t.body
	t.mtx.Unlock()
	return body.Read(b)
}

func (t *tcpConn) Write(b []byte) (int, error) {
	return t.writeFlush(b)
}

func (t *tcpConn) CloseWrite() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.closed {
		return net.ErrClosed
	}
	if closer, ok := t.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Wire limits: the UDP padding length is a uint16 in the frame header.
const (
	MaxUDPPadding = 65535
)

// ValidatePadding rejects ranges that would silently corrupt the stream.
func ValidatePadding(name string, min, max, limit int) error {
	if min < 0 || max < min || max > limit {
		return fmt.Errorf("%s: need 0 <= min <= max <= %d, got [%d, %d]", name, limit, min, max)
	}
	return nil
}

// closeOnCancel привязывает время жизни стрима к запросу, как соединение
// VLESS привязано к своему сокету: как только клиент сбросил стрим
// (RST_STREAM) или умерло h2/h3-соединение целиком, ctx запроса
// отменяется, и стрим закрывается сразу, не дожидаясь, пока до этого
// дойдёт чтение или запись. Выходит, когда стрим закрылся сам (done).
func closeOnCancel(ctx context.Context, c io.Closer, done <-chan struct{}) {
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
}
