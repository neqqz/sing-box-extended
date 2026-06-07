package failover

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

type dial func() (net.Conn, error)

type failoverConn struct {
	net.Conn
	ctx     context.Context
	dial    dial
	onClose func()

	readIndex    uint32
	readBuffer   *bytes.Buffer
	writeIndex   uint32
	writeBuffers [BufferSize][]byte

	await    chan struct{}
	awaitMtx sync.Mutex

	err error

	once sync.Once
	mtx  sync.RWMutex
}

func NewFailoverConn(ctx context.Context, conn net.Conn, dial dial, onClose func()) *failoverConn {
	var writeBuffers [BufferSize][]byte
	for i := range BufferSize {
		writeBuffers[i] = make([]byte, 0, 1024)
	}
	return &failoverConn{
		Conn:         conn,
		ctx:          ctx,
		dial:         dial,
		readBuffer:   bytes.NewBuffer(make([]byte, 0, 1024)),
		writeBuffers: writeBuffers,
		onClose:      onClose,
	}
}

func (c *failoverConn) Read(b []byte) (int, error) {
	for {
		c.mtx.RLock()
		conn := c.Conn
		n, err := c.read(conn, b)
		if err != nil {
			if err == SessionClosed {
				c.err = io.EOF
				conn.Close()
				c.mtx.RUnlock()
				return 0, c.err
			}
			c.mtx.RUnlock()
			err = c.awaitConn(conn)
			if err != nil {
				return 0, err
			}
			continue
		}
		c.readIndex++
		c.mtx.RUnlock()
		return n, err
	}
}

func (c *failoverConn) Write(b []byte) (int, error) {
	for {
		c.mtx.RLock()
		conn := c.Conn
		n, err := c.write(conn, b)
		if err != nil {
			c.mtx.RUnlock()
			err = c.awaitConn(conn)
			if err != nil {
				return 0, err
			}
			continue
		}
		writeIndex := c.writeIndex % BufferSize
		c.writeBuffers[writeIndex] = append(c.writeBuffers[writeIndex][:0], b...)
		c.writeIndex++
		c.mtx.RUnlock()
		return n, err
	}
}

func (c *failoverConn) RestoreConn(conn net.Conn) error {
	c.Conn.Close()
	c.mtx.Lock()
	defer c.mtx.Unlock()
	_, err := conn.Write([]byte{
		byte(c.readIndex >> 24),
		byte(c.readIndex >> 16),
		byte(c.readIndex >> 8),
		byte(c.readIndex),
	})
	if err != nil {
		return err
	}
	var data [4]byte
	_, err = io.ReadFull(conn, data[:])
	if err != nil {
		return err
	}
	writeIndex := binary.BigEndian.Uint32(data[:])
	buffers := make([][]byte, 0, BufferSize)
	for writeIndex != c.writeIndex {
		if len(buffers) == BufferSize {
			return SessionBroken
		}
		buffers = append(buffers, c.writeBuffers[writeIndex%BufferSize])
		writeIndex++
	}
	for _, buffer := range buffers {
		_, err = c.write(conn, buffer)
		if err != nil {
			return err
		}
	}
	c.Conn = conn
	if c.await != nil {
		close(c.await)
		c.await = nil
	}
	return nil
}

func (c *failoverConn) Close() error {
	c.once.Do(func() {
		c.mtx.RLock()
		if c.onClose != nil {
			c.onClose()
		}
		c.err = io.EOF
		c.mtx.RUnlock()
		c.Write([]byte{})
	})
	return nil
}

func (c *failoverConn) read(conn net.Conn, b []byte) (int, error) {
	if c.readBuffer.Len() == 0 {
		c.readBuffer.Reset()
		var data [2]byte
		_, err := io.ReadFull(conn, data[:])
		if err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint16(data[:])
		if n == 0 {
			return 0, SessionClosed
		}
		_, err = io.CopyN(c.readBuffer, conn, int64(n))
		if err != nil {
			return 0, err
		}
	}
	return c.readBuffer.Read(b)
}

func (c *failoverConn) write(conn net.Conn, b []byte) (int, error) {
	buffer := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buffer, uint16(len(b)))
	copy(buffer[2:], b)
	n, err := conn.Write(buffer)
	return n - 2, err
}

func (c *failoverConn) awaitConn(oldConn net.Conn) error {
	c.awaitMtx.Lock()
	defer c.awaitMtx.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.Conn != oldConn {
		return c.ctx.Err()
	}
	oldConn.Close()
	timer := time.NewTimer(C.TCPConnectTimeout)
	defer timer.Stop()
	if c.dial != nil {
		for {
			select {
			case <-c.ctx.Done():
				return c.ctx.Err()
			case <-timer.C:
				c.err = SessionExpired
				return c.err
			default:
			}
			conn, err := c.dial()
			if err != nil {
				if err == SessionNotFound {
					c.err = err
					return err
				}
				continue
			}
			err = c.RestoreConn(conn)
			if err != nil {
				if err == SessionBroken {
					c.err = err
					return err
				}
				continue
			}
			return nil
		}
	} else {
		c.await = make(chan struct{})
		select {
		case <-c.await:
		case <-timer.C:
			c.err = SessionExpired
			return c.err
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
	return nil
}
