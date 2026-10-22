package trusttunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

const udpHeaderLen = 22

var (
	_ N.NetPacketConn = (*packetConn)(nil)
	_ N.FrontHeadroom = (*packetConn)(nil)
	_ N.NetPacketConn = (*quicPacketConn)(nil)
	_ N.FrontHeadroom = (*quicPacketConn)(nil)
)

type datagramStream interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Close() error
}

type quicPacketConn struct {
	stream     datagramStream
	ctx        context.Context
	cancel     context.CancelFunc
	remoteAddr net.Addr
	localAddr  net.Addr
	paddingMin int
	paddingMax int
	closed     atomic.Bool
	closeFn    func()
}

func (u *quicPacketConn) FrontHeadroom() int {
	return udpHeaderLen
}

func (u *quicPacketConn) RemoteAddr() net.Addr {
	if u.remoteAddr != nil {
		return u.remoteAddr
	}
	return &net.UDPAddr{}
}

func (u *quicPacketConn) LocalAddr() net.Addr {
	if u.localAddr != nil {
		return u.localAddr
	}
	return &net.UDPAddr{}
}

func (u *quicPacketConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (u *quicPacketConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (u *quicPacketConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }
func (u *quicPacketConn) NeedAdditionalReadDeadline() bool { return true }

func (u *quicPacketConn) Close() error {
	if u.closed.CompareAndSwap(false, true) {
		u.cancel()
		_ = u.stream.Close()
		if u.closeFn != nil {
			u.closeFn()
		}
	}
	return nil
}

func (u *quicPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if u.closed.Load() {
		return destination, net.ErrClosed
	}
	for {
		b, err := u.stream.ReceiveDatagram(u.ctx)
		if err != nil {
			return destination, err
		}
		if len(b) < udpHeaderLen {
			continue
		}
		payloadLen := int(binary.BigEndian.Uint16(b[0:2]))
		paddingLen := int(binary.BigEndian.Uint16(b[2:4]))
		_ = paddingLen
		if len(b) < udpHeaderLen+payloadLen {
			continue
		}
		var ip [16]byte
		copy(ip[:], b[4:20])
		destination.Addr = parse16BytesIP(ip)
		destination.Port = binary.BigEndian.Uint16(b[20:22])
		common.Must1(buffer.Write(b[udpHeaderLen : udpHeaderLen+payloadLen]))
		return destination, nil
	}
}

func (u *quicPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := u.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	if destination.Addr.IsValid() {
		addr = destination.UDPAddr()
	} else {
		addr = destination
	}
	return buffer.Len(), addr, nil
}

func (u *quicPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if u.closed.Load() {
		return net.ErrClosed
	}
	if !destination.IsIP() {
		return E.New("only support IP")
	}
	payloadLen := buffer.Len()
	if payloadLen > math.MaxUint16 {
		return E.New("payload too large")
	}
	paddingLen := randomUDPPaddingLength(u.paddingMin, u.paddingMax)
	destIP := buildPaddingIP(destination.Addr)

	var header [udpHeaderLen]byte
	binary.BigEndian.PutUint16(header[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(header[2:4], uint16(paddingLen))
	copy(header[4:20], destIP[:])
	binary.BigEndian.PutUint16(header[20:22], destination.Port)

	totalLen := udpHeaderLen + payloadLen + paddingLen
	out := buf.NewSize(totalLen)
	defer out.Release()

	common.Must1(out.Write(header[:]))
	common.Must1(out.Write(buffer.Bytes()))
	if paddingLen > 0 {
		common.Must1(out.Write(randomUDPPadding(paddingLen)))
	}

	err := u.stream.SendDatagram(out.Bytes())
	if err != nil && paddingLen > 0 {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			binary.BigEndian.PutUint16(header[2:4], 0)
			outNoPad := buf.NewSize(udpHeaderLen + payloadLen)
			defer outNoPad.Release()
			common.Must1(outNoPad.Write(header[:]))
			common.Must1(outNoPad.Write(buffer.Bytes()))
			err = u.stream.SendDatagram(outNoPad.Bytes())
		}
	}
	return err
}

func (u *quicPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type packetConn struct {
	httpConn
	paddingMin int
	paddingMax int
}

func (u *packetConn) FrontHeadroom() int {
	return udpHeaderLen
}

func (u *packetConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = u.waitCreated()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return u.readPacket(buffer)
}

func (u *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := u.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	if destination.Addr.IsValid() {
		addr = destination.UDPAddr()
	} else {
		addr = destination
	}
	return buffer.Len(), addr, nil
}

func (u *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return u.writePacket(buffer, destination)
}

func (u *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *packetConn) readPacket(buffer *buf.Buffer) (address M.Socksaddr, err error) {
	u.mtx.Lock()
	if u.closed || u.body == nil {
		u.mtx.Unlock()
		return address, net.ErrClosed
	}
	body := u.body
	u.mtx.Unlock()

	var header [udpHeaderLen]byte
	_, err = io.ReadFull(body, header[:])
	if err != nil {
		return
	}
	payloadLen := int(binary.BigEndian.Uint16(header[0:2]))
	paddingLen := int(binary.BigEndian.Uint16(header[2:4]))
	var ip [16]byte
	copy(ip[:], header[4:20])
	address.Addr = parse16BytesIP(ip)
	address.Port = binary.BigEndian.Uint16(header[20:22])

	_, err = buffer.ReadFullFrom(body, payloadLen)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		err = rw.SkipN(body, paddingLen)
	}
	return
}

func (u *packetConn) writePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsIP() {
		return E.New("only support IP")
	}
	payloadLen := buffer.Len()
	if payloadLen > math.MaxUint16 {
		return E.New("payload too large")
	}
	paddingLen := randomUDPPaddingLength(u.paddingMin, u.paddingMax)
	destIP := buildPaddingIP(destination.Addr)

	var header [udpHeaderLen]byte
	binary.BigEndian.PutUint16(header[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(header[2:4], uint16(paddingLen))
	copy(header[4:20], destIP[:])
	binary.BigEndian.PutUint16(header[20:22], destination.Port)

	padding := randomUDPPadding(paddingLen)
	out := buf.NewSize(udpHeaderLen + payloadLen + paddingLen)
	defer out.Release()
	common.Must1(out.Write(header[:]))
	common.Must1(out.Write(buffer.Bytes()))
	if paddingLen > 0 {
		common.Must1(out.Write(padding))
	}
	return u.writeChunks(out.Bytes())
}
