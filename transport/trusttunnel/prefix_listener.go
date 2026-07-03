package trusttunnel

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const (
	// TLS record header(5) + Handshake header(4) + client_version(2) = 11 bytes offset to Random.
	// Random is 32 bytes: buf[11:43].
	tlsClientRandomOffset = 11
	tlsClientRandomEnd    = 43
	tlsPeekLen            = tlsClientRandomEnd // enough to verify + read full Random
	tlsPeekTimeout        = 5 * time.Second
)

// PrefixListener wraps a net.Listener to validate TLS ClientHello.Random prefix
// BEFORE passing the connection to the TLS layer.  Connections whose Random
// does not match are silently closed, making the server invisible to scanners.
// If prefix is empty, the inner listener is returned unchanged.
type PrefixListener struct {
	net.Listener
	prefix []byte
	mask   []byte
	logger logger.ContextLogger
}

// NewPrefixListener parses the "hex" or "hex/mask_hex" format (same as
// outbound client_random_prefix) and returns a wrapping listener.
func NewPrefixListener(inner net.Listener, raw string, log logger.ContextLogger) (net.Listener, error) {
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
	return &PrefixListener{
		Listener: inner,
		prefix:   prefix,
		mask:     mask,
		logger:   log,
	}, nil
}

// Accept loops until it gets a connection that passes the prefix check,
// or until the underlying listener returns an error.
func (l *PrefixListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peeked, ok := l.checkRandom(conn)
		if !ok {
			conn.Close()
			continue
		}
		// Return a buffered conn that replays peeked bytes to the TLS layer.
		return &peekedConn{Conn: conn, buf: peeked}, nil
	}
}

// checkRandom peeks at the TLS ClientHello and verifies the Random prefix/mask.
// Returns the peeked bytes on success so they can be replayed.
func (l *PrefixListener) checkRandom(conn net.Conn) ([]byte, bool) {
	if err := conn.SetReadDeadline(time.Now().Add(tlsPeekTimeout)); err != nil {
		return nil, false
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	buf := make([]byte, tlsPeekLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, false
	}

	// Minimal sanity: TLS content_type=0x16 (Handshake), handshake_type=0x01 (ClientHello).
	if buf[0] != 0x16 || buf[5] != 0x01 {
		l.logger.Debug("trusttunnel inbound: dropping non-ClientHello TCP connection")
		return nil, false
	}

	random := buf[tlsClientRandomOffset:tlsClientRandomEnd]
	for i, b := range l.prefix {
		if random[i]&l.mask[i] != b&l.mask[i] {
			l.logger.Debug("trusttunnel inbound: client_random_prefix mismatch, dropping")
			return nil, false
		}
	}
	return buf, true
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
