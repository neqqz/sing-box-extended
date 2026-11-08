package trusttunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
	randv2 "math/rand/v2"
)

const (
	UDPMagicAddress           = "_udp2"
	HealthCheckMagicAddress   = "_check"
	ICMPMagicAddress          = "_icmp"
	DefaultHealthCheckTimeout = 7 * time.Second
	DefaultSessionTimeout     = 30 * time.Second
	DefaultKeepAlivePeriod    = 10 * time.Second

	AuthBasicPrefix         = "Basic "
	ProxyAuthRealm          = "Authorization Required"
	ProxyAuthenticateHeader = "Basic realm=\"Authorization Required\""

	MaxUDPPadding = 255
)

func buildAuth(username, password string) string {
	credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return AuthBasicPrefix + credentials
}

func parseAuth(auth string) (string, bool) {
	if len(auth) < len(AuthBasicPrefix) || !strings.EqualFold(auth[:len(AuthBasicPrefix)], AuthBasicPrefix) {
		return "", false
	}
	return strings.TrimSpace(auth[len(AuthBasicPrefix):]), true
}

func parse16BytesIP(rawIP [16]byte) netip.Addr {
	allZeroPrefix := true
	for i := 0; i < 12; i++ {
		if rawIP[i] != 0 {
			allZeroPrefix = false
			break
		}
	}
	if allZeroPrefix {
		return netip.AddrFrom4(*(*[4]byte)(rawIP[12:16]))
	}
	return netip.AddrFrom16(rawIP)
}

func buildPaddingIP(addr netip.Addr) (paddedIP [16]byte) {
	if addr.Is4() {
		copy(paddedIP[12:], addr.AsSlice())
	} else if addr.Is6() {
		copy(paddedIP[:], addr.AsSlice())
	}
	return
}

func randomUDPPaddingLength(min, max int) int {
	if max <= 0 || min < 0 || max < min {
		return 0
	}
	if max == min {
		return min
	}
	return min + randv2.IntN(max-min+1)
}

const asciiLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomASCII(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = asciiLetters[randv2.IntN(len(asciiLetters))]
	}
	return b
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
