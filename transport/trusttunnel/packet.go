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
	_ N.NetPacketConn = (*clientPacketConn)(nil)
	_ N.FrontHeadroom = (*clientPacketConn)(nil)
)

type clientPacketConn struct {
	httpConn
	paddingMin int
	paddingMax int
}

func (u *clientPacketConn) FrontHeadroom() int {
	return udpHeaderLen
}

func (u *clientPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = u.waitCreated()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return u.readPacketFromServer(buffer)
}

func (u *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (u *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return u.writePacketToServer(buffer, destination)
}

func (u *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *clientPacketConn) readPacketFromServer(buffer *buf.Buffer) (source M.Socksaddr, err error) {
	var header [udpHeaderLen]byte
	_, err = io.ReadFull(u.body, header[:])
	if err != nil {
		return
	}
	payloadLen := int(binary.BigEndian.Uint16(header[0:2]))
	paddingLen := int(binary.BigEndian.Uint16(header[2:4]))
	var srcIP [16]byte
	copy(srcIP[:], header[4:20])
	source.Addr = parse16BytesIP(srcIP)
	source.Port = binary.BigEndian.Uint16(header[20:22])

	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		err = rw.SkipN(u.body, paddingLen)
	}
	return
}

func (u *clientPacketConn) writePacketToServer(buffer *buf.Buffer, destination M.Socksaddr) error {
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

	padding, err := randomUDPPadding(paddingLen)
	if err != nil {
		return err
	}
	out := buf.NewSize(udpHeaderLen + payloadLen + paddingLen)
	defer out.Release()
	common.Must1(out.Write(header[:]))
	common.Must1(out.Write(buffer.Bytes()))
	if paddingLen > 0 {
		common.Must1(out.Write(padding))
	}
	return u.writeChunks(out.Bytes())
}

var (
	_ N.NetPacketConn = (*serverPacketConn)(nil)
	_ N.FrontHeadroom = (*serverPacketConn)(nil)
)

type serverPacketConn struct {
	httpConn
	paddingMin int
	paddingMax int
}

func (u *serverPacketConn) FrontHeadroom() int {
	return udpHeaderLen
}

func (u *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = u.waitCreated()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return u.readPacketFromClient(buffer)
}

func (u *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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

func (u *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return u.writePacketToClient(buffer, destination)
}

func (u *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *serverPacketConn) readPacketFromClient(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var header [udpHeaderLen]byte
	_, err = io.ReadFull(u.body, header[:])
	if err != nil {
		return
	}
	payloadLen := int(binary.BigEndian.Uint16(header[0:2]))
	paddingLen := int(binary.BigEndian.Uint16(header[2:4]))
	var destIP [16]byte
	copy(destIP[:], header[4:20])
	destination.Addr = parse16BytesIP(destIP)
	destination.Port = binary.BigEndian.Uint16(header[20:22])

	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		err = rw.SkipN(u.body, paddingLen)
	}
	return
}

func (u *serverPacketConn) writePacketToClient(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	payloadLen := buffer.Len()
	if payloadLen > math.MaxUint16 {
		return E.New("payload too large")
	}
	paddingLen := randomUDPPaddingLength(u.paddingMin, u.paddingMax)
	srcIP := buildPaddingIP(source.Addr)

	var header [udpHeaderLen]byte
	binary.BigEndian.PutUint16(header[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(header[2:4], uint16(paddingLen))
	copy(header[4:20], srcIP[:])
	binary.BigEndian.PutUint16(header[20:22], source.Port)

	padding, err := randomUDPPadding(paddingLen)
	if err != nil {
		return err
	}
	out := buf.NewSize(udpHeaderLen + payloadLen + paddingLen)
	defer out.Release()
	common.Must1(out.Write(header[:]))
	common.Must1(out.Write(buffer.Bytes()))
	if paddingLen > 0 {
		common.Must1(out.Write(padding))
	}
	return u.writeChunks(out.Bytes())
}
