package trusttunnel

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	UDPMagicAddress           = "_udp2"
	ICMPMagicAddress          = "_icmp"
	HealthCheckMagicAddress   = "_check"
	DefaultConnectionTimeout  = 30 * time.Second
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
	writer       io.Writer
	flusher      http.Flusher
	body         io.ReadCloser
	setupOnce    sync.Once
	created      chan struct{}
	createErr    error
	cancelFn     func()
	closeFn      func()
	remoteAddr   net.Addr
	localAddr    net.Addr
	deadline     *time.Timer
	deadlineLock sync.Mutex
	done         chan struct{}
	closed       bool
	mtx          sync.Mutex
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

func (h *httpConn) Body() io.ReadCloser {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.body
}

func (h *httpConn) Close() error {
	h.mtx.Lock()
	h.closed = true
	h.mtx.Unlock()
	h.setup(nil, net.ErrClosed)
	if closer, ok := h.writer.(io.Closer); ok {
		_ = closer.Close()
	}
	if h.body != nil {
		_ = h.body.Close()
	}
	if h.cancelFn != nil {
		h.cancelFn()
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

func (h *httpConn) SetDeadline(t time.Time) error {
	h.deadlineLock.Lock()
	defer h.deadlineLock.Unlock()
	if t.IsZero() {
		if h.deadline != nil {
			h.deadline.Stop()
			h.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if h.deadline != nil {
		h.deadline.Reset(d)
		return nil
	}
	h.deadline = time.AfterFunc(d, func() { h.Close() })
	return nil
}

func (h *httpConn) SetReadDeadline(t time.Time) error  { return h.SetDeadline(t) }
func (h *httpConn) SetWriteDeadline(t time.Time) error { return h.SetDeadline(t) }

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
