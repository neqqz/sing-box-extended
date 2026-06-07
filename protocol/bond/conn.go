package bond

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

type bondedConn struct {
	conns          []net.Conn
	downloadRatios []uint8
	uploadRatios   []uint8

	readBuffer *bytes.Buffer
}

func NewBondedConn(conns []net.Conn, downloadRatios, uploadRatios []uint8) *bondedConn {
	return &bondedConn{
		conns:          conns,
		downloadRatios: downloadRatios,
		uploadRatios:   uploadRatios,
		readBuffer:     bytes.NewBuffer(make([]byte, 0, 4096)),
	}
}

func (c *bondedConn) Read(b []byte) (n int, err error) {
	if c.readBuffer.Len() == 0 {
		c.readBuffer.Reset()
		var header [2]byte
		_, err := io.ReadFull(c.conns[0], header[:])
		if err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		chunkLens := splitByRatios(size, c.downloadRatios)
		total := 0
		for i, chunkLen := range chunkLens {
			if chunkLen == 0 {
				continue
			}
			n, err := io.CopyN(c.readBuffer, c.conns[i], int64(chunkLen))
			total += int(n)
			if err != nil {
				return total, err
			}
		}
	}
	return c.readBuffer.Read(b)
}

func (c *bondedConn) Write(b []byte) (n int, err error) {
	chunkLens := splitByRatios(len(b), c.uploadRatios)
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(b)))
	_, err = c.conns[0].Write(header[:])
	if err != nil {
		return 0, err
	}
	total := 0
	for i, chunkLen := range chunkLens {
		if chunkLen == 0 {
			continue
		}
		chunk := b[total : total+chunkLen]
		conn := c.conns[i]
		subTotal := 0
		for subTotal < len(chunk) {
			n, err := conn.Write(chunk[subTotal:])
			subTotal += n
			total += n
			if err != nil {
				return total, err
			}
			if n == 0 {
				return total, io.ErrUnexpectedEOF
			}
		}
	}
	return total, err
}

func (c *bondedConn) Close() error {
	errs := make([]error, 0)
	for _, conn := range c.conns {
		err := conn.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *bondedConn) LocalAddr() net.Addr {
	return nil
}

func (c *bondedConn) RemoteAddr() net.Addr {
	return nil
}

func (c *bondedConn) SetDeadline(t time.Time) error {
	errs := make([]error, 0)
	for _, conn := range c.conns {
		err := conn.SetDeadline(t)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *bondedConn) SetReadDeadline(t time.Time) error {
	errs := make([]error, 0)
	for _, conn := range c.conns {
		err := conn.SetReadDeadline(t)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *bondedConn) SetWriteDeadline(t time.Time) error {
	errs := make([]error, 0)
	for _, conn := range c.conns {
		err := conn.SetWriteDeadline(t)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func splitByRatios(number int, ratios []uint8) []int {
	result := make([]int, len(ratios))
	remaining := number
	for i := 0; i < len(ratios)-1; i++ {
		part := number * int(ratios[i]) / 100
		result[i] = part
		remaining -= part
	}
	result[len(ratios)-1] = remaining
	return result
}
