package trusttunnel

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	UDPMagicAddress           = "_udp2"
	HealthCheckMagicAddress   = "_check"
	DefaultHealthCheckTimeout = 7 * time.Second
	DefaultSessionTimeout     = 30 * time.Second
)

func buildAuth(username string, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	return
}

func parse16BytesIP(buffer [16]byte) netip.Addr {
	var zeroPrefix [12]byte
	isIPv4 := bytes.HasPrefix(buffer[:], zeroPrefix[:])
	isIPv4 = isIPv4 && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1)
	if isIPv4 {
		return netip.AddrFrom4([4]byte(buffer[12:16]))
	}
	return netip.AddrFrom16(buffer)
}

func buildPaddingIP(addr netip.Addr) (buffer [16]byte) {
	if addr.Is6() {
		return addr.As16()
	}
	ipv4 := addr.As4()
	copy(buffer[12:16], ipv4[:])
	return buffer
}

// randomUDPPaddingLength возвращает случайную длину паддинга в [min, max]
// (в байтах). Криптографически случайную — паддинг живёт внутри TLS/QUIC,
// но лишний предсказуемый паттерн размеров лучше не оставлять и там.
// 0, если паддинг выключен (max<=0) или диапазон некорректен.
func randomUDPPaddingLength(min, max int) int {
	if max <= 0 || min < 0 || max < min {
		return 0
	}
	if max == min {
		return min
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// randomUDPPadding возвращает n случайных байт паддинга (nil, если n<=0).
// Раньше эта функция сама писала в w отдельным Write; теперь байты
// возвращаются вызывающему, чтобы он мог передать их в writeChunks вместе
// с header/payload — одним write-локом, без гонки с Close().
func randomUDPPadding(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	padding := make([]byte, n)
	if _, err := crand.Read(padding); err != nil {
		return nil, err
	}
	return padding, nil
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
	if h.body != nil {
		return nil
	}
	return h.createErr
}

func (h *httpConn) Close() error {
	// Record ErrClosed before cancelling, so the request goroutine cannot win
	// with context.Canceled. Cancel before locking: a Write blocked on peer flow
	// control holds h.mtx, and only aborting the request unblocks it.
	h.setup(nil, net.ErrClosed)
	if h.cancelFn != nil {
		h.cancelFn()
	}
	h.mtx.Lock()
	h.closed = true
	h.mtx.Unlock()
	if closer, ok := h.writer.(io.Closer); ok {
		_ = closer.Close()
	}
	if h.body != nil {
		_ = h.body.Close()
	}
	if h.closeFn != nil {
		h.closeFn()
	}
	if h.done != nil {
		select {
		case <-h.done:
		default:
			close(h.done)
		}
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

var _ net.Conn = (*tcpConn)(nil)

type tcpConn struct{ httpConn }

func (t *tcpConn) Read(b []byte) (n int, err error) {
	if err = t.waitCreated(); err != nil {
		return 0, err
	}
	return t.body.Read(b)
}

func (t *tcpConn) Write(b []byte) (int, error) {
	return t.writeFlush(b)
}

// Wire limits: the UDP padding length is a uint16 in the frame header, the
// h2 DATA pad length is one byte (RFC 9113 §6.1).
const (
	MaxUDPPadding  = 65535
	MaxDataPadding = 255
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
