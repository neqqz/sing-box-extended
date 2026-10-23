package obfs

import (
	randv2 "math/rand/v2"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	N "github.com/sagernet/sing/common/network"
)

const DefaultJitterPackets = 5

// NewJitterConn возвращает net.Conn с задержками на первых packets пакетах.
// Если maxMS <= 0, возвращает исходный conn без обёртки.
func NewJitterConn(conn net.Conn, minMS, maxMS, packets int) net.Conn {
	if maxMS <= 0 || conn == nil {
		return conn
	}
	if minMS < 0 {
		minMS = 0
	}
	if minMS > maxMS {
		minMS, maxMS = maxMS, minMS
	}
	if packets == 0 {
		packets = DefaultJitterPackets
	}
	return &jitterConn{
		Conn:    conn,
		minMS:   minMS,
		maxMS:   maxMS,
		packets: packets,
	}
}

type jitterConn struct {
	net.Conn
	minMS   int
	maxMS   int
	packets int
	count   atomic.Int64
}

func (c *jitterConn) Write(b []byte) (int, error) {
	if c.packets < 0 {
		sleepJitter(c.minMS, c.maxMS)
	} else if c.count.Load() <= int64(c.packets) {
		if int(c.count.Add(1)) <= c.packets {
			sleepJitter(c.minMS, c.maxMS)
		}
	}
	return c.Conn.Write(b)
}

func (c *jitterConn) CloseWrite() error {
	return N.CloseWrite(c.Conn)
}

func (c *jitterConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, syscall.EINVAL
}

func (c *jitterConn) Upstream() any {
	return c.Conn
}

// NewJitterPacketConn возвращает net.PacketConn с задержками на первых packets датаграммах.
// Если maxMS <= 0, возвращает исходный conn без обёртки.
func NewJitterPacketConn(conn net.PacketConn, minMS, maxMS, packets int) net.PacketConn {
	if maxMS <= 0 || conn == nil {
		return conn
	}
	if minMS < 0 {
		minMS = 0
	}
	if minMS > maxMS {
		minMS, maxMS = maxMS, minMS
	}
	if packets == 0 {
		packets = DefaultJitterPackets
	}
	return &jitterPacketConn{
		PacketConn: conn,
		minMS:      minMS,
		maxMS:      maxMS,
		packets:    packets,
	}
}

type jitterPacketConn struct {
	net.PacketConn
	minMS   int
	maxMS   int
	packets int
	count   atomic.Int64
}

func (c *jitterPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.packets < 0 {
		sleepJitter(c.minMS, c.maxMS)
	} else if c.count.Load() <= int64(c.packets) {
		if int(c.count.Add(1)) <= c.packets {
			sleepJitter(c.minMS, c.maxMS)
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *jitterPacketConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, syscall.EINVAL
}

func (c *jitterPacketConn) Upstream() any {
	return c.PacketConn
}

func sleepJitter(minMS, maxMS int) {
	span := maxMS - minMS
	var ms int
	if span > 0 {
		ms = minMS + randv2.IntN(span+1)
	} else {
		ms = minMS
	}
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}
