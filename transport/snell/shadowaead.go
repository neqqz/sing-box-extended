package snell

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
)

// payloadSizeMask is the maximum size of payload in bytes.
// 16*1024 - 1
// >= 2+aead.Overhead()+payloadSizeMask+aead.Overhead()

// ErrZeroChunk is returned when a zero-length chunk is read, which snell uses
// as an end-of-stream signal.
var ErrZeroChunk = errors.New("zero chunk")

// Cipher is the AEAD cipher abstraction used by the shadowaead stream.
type Cipher interface {
	KeySize() int
	SaltSize() int
	Encrypter(salt []byte) (cipher.AEAD, error)
	Decrypter(salt []byte) (cipher.AEAD, error)
}

const (
	payloadSizeMask = 0x3FFF
	bufSize         = 17 * 1024
)

type aeadWriter struct {
	io.Writer
	cipher.AEAD
	nonce [32]byte // should be sufficient for most nonce sizes
}

// newAEADWriter wraps an io.Writer with authenticated encryption.
func newAEADWriter(w io.Writer, aead cipher.AEAD) *aeadWriter {
	return &aeadWriter{Writer: w, AEAD: aead}
}

// Write encrypts p and writes to the embedded io.Writer.
func (w *aeadWriter) Write(p []byte) (n int, err error) {
	b := buf.Get(bufSize)
	defer buf.Put(b)
	nonce := w.nonce[:w.NonceSize()]
	tag := w.Overhead()
	off := 2 + tag
	if len(p) == 0 {
		b = b[:off]
		b[0], b[1] = byte(0), byte(0)
		w.Seal(b[:0], nonce, b[:2], nil)
		increment(nonce)
		_, err = w.Writer.Write(b)
		return
	}
	for nr := 0; n < len(p) && err == nil; n += nr {
		nr = payloadSizeMask
		if n+nr > len(p) {
			nr = len(p) - n
		}
		b = b[:off+nr+tag]
		b[0], b[1] = byte(nr>>8), byte(nr)
		w.Seal(b[:0], nonce, b[:2], nil)
		increment(nonce)
		w.Seal(b[:off], nonce, p[n:n+nr], nil)
		increment(nonce)
		_, err = w.Writer.Write(b)
	}
	return
}

type aeadReader struct {
	io.Reader
	cipher.AEAD
	nonce [32]byte // should be sufficient for most nonce sizes
	buf   []byte   // to be put back into bufPool
	off   int      // offset to unconsumed part of buf
}

// newAEADReader wraps an io.Reader with authenticated decryption.
func newAEADReader(r io.Reader, aead cipher.AEAD) *aeadReader {
	return &aeadReader{Reader: r, AEAD: aead}
}

// read and decrypt a record into p. len(p) >= max payload size + AEAD overhead.
func (r *aeadReader) read(p []byte) (int, error) {
	nonce := r.nonce[:r.NonceSize()]
	tag := r.Overhead()
	p = p[:2+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return 0, err
	}
	_, err := r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return 0, err
	}
	size := (int(p[0])<<8 + int(p[1])) & payloadSizeMask
	if size == 0 {
		return 0, ErrZeroChunk
	}
	p = p[:size+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return 0, err
	}
	_, err = r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to p.
func (r *aeadReader) Read(p []byte) (int, error) {
	if r.buf == nil {
		if len(p) >= payloadSizeMask+r.Overhead() {
			return r.read(p)
		}
		b := buf.Get(bufSize)
		n, err := r.read(b)
		if err != nil {
			buf.Put(b)
			return 0, err
		}
		r.buf = b[:n]
		r.off = 0
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	if r.off == len(r.buf) {
		buf.Put(r.buf[:cap(r.buf)])
		r.buf = nil
	}
	return n, nil
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// aeadConn wraps a stream-oriented net.Conn with the shadowaead cipher.
type aeadConn struct {
	net.Conn
	Cipher
	r *aeadReader
	w *aeadWriter
}

// newAEADConn wraps a stream-oriented net.Conn with cipher.
func newAEADConn(c net.Conn, ciph Cipher) *aeadConn {
	return &aeadConn{Conn: c, Cipher: ciph}
}

func (c *aeadConn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}
	c.r = newAEADReader(c.Conn, aead)
	return nil
}

func (c *aeadConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *aeadConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	c.w = newAEADWriter(c.Conn, aead)
	return nil
}

func (c *aeadConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}
