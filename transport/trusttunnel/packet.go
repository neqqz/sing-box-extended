package trusttunnel

import (
	"encoding/binary"
	"io"
	"math"
	"net"

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
)

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
