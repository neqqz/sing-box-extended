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
	return 4 + 2 + 16 + 2 + 16 + 2 + 1 + math.MaxUint8
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
	return buffer.Len(), destination.UDPAddr(), nil
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

func (u *clientPacketConn) readPacketFromServer(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var header [42]byte
	_, err = io.ReadFull(u.body, header[:])
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header[0:4])
	paddingLen := binary.BigEndian.Uint16(header[4:6])
	var sourceAddressBuffer [16]byte
	copy(sourceAddressBuffer[:], header[6:22])
	destination.Addr = parse16BytesIP(sourceAddressBuffer)
	destination.Port = binary.BigEndian.Uint16(header[22:24])
	const minHeaderLen = 2 + 16 + 2 + 16 + 2
	if uint64(length) < uint64(minHeaderLen)+uint64(paddingLen) {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	payloadLen := int(length) - minHeaderLen - int(paddingLen)
	if payloadLen > math.MaxUint16 {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		err = rw.SkipN(u.body, int(paddingLen))
	}
	return
}

func (u *clientPacketConn) writePacketToServer(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	paddingLen := randomUDPPaddingLength(u.paddingMin, u.paddingMax)
	payloadLen := buffer.Len()
	appLen := len(appName)
	lengthField := uint32(2 + 16 + 2 + 16 + 2 + 1 + appLen + payloadLen + paddingLen)
	destinationAddress := buildPaddingIP(source.Addr)
	var header [43 + math.MaxUint8]byte
	hdr := header[:43+appLen]
	binary.BigEndian.PutUint32(hdr[0:4], lengthField)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(paddingLen))
	// hdr[6:24] are 18 zero bytes
	clear(hdr[6:24])
	copy(hdr[24:40], destinationAddress[:])
	binary.BigEndian.PutUint16(hdr[40:42], source.Port)
	hdr[42] = uint8(appLen)
	copy(hdr[43:], appName)
	padding, err := randomUDPPadding(paddingLen)
	if err != nil {
		return err
	}
	out := buf.NewSize(len(hdr) + payloadLen + paddingLen)
	defer out.Release()
	common.Must1(out.Write(hdr))
	common.Must1(out.Write(buffer.Bytes()))
	if paddingLen > 0 {
		common.Must1(out.Write(padding))
	}
	return u.writeFlush(out.Bytes())
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
	return 4 + 2 + 16 + 2 + 16 + 2
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
	return buffer.Len(), destination.UDPAddr(), nil
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
	var header [43]byte
	_, err = io.ReadFull(u.body, header[:])
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header[0:4])
	paddingLen := binary.BigEndian.Uint16(header[4:6])
	// header[6:24] are 18 zero bytes
	var destinationAddressBuffer [16]byte
	copy(destinationAddressBuffer[:], header[24:40])
	destination.Addr = parse16BytesIP(destinationAddressBuffer)
	destination.Port = binary.BigEndian.Uint16(header[40:42])
	appNameLen := header[42]
	if appNameLen > 0 {
		err = rw.SkipN(u.body, int(appNameLen))
		if err != nil {
			return M.Socksaddr{}, err
		}
	}
	minHeaderLen := 2 + 16 + 2 + 16 + 2 + 1 + int(appNameLen)
	if uint64(length) < uint64(minHeaderLen)+uint64(paddingLen) {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	payloadLen := int(length) - minHeaderLen - int(paddingLen)
	if payloadLen > math.MaxUint16 {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	if err != nil {
		return
	}
	if paddingLen > 0 {
		err = rw.SkipN(u.body, int(paddingLen))
	}
	return
}

func (u *serverPacketConn) writePacketToClient(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	paddingLen := randomUDPPaddingLength(u.paddingMin, u.paddingMax)
	payloadLen := buffer.Len()
	lengthField := uint32(2 + 16 + 2 + 16 + 2 + payloadLen + paddingLen)
	sourceAddress := buildPaddingIP(source.Addr)
	var header [42]byte
	binary.BigEndian.PutUint32(header[0:4], lengthField)
	binary.BigEndian.PutUint16(header[4:6], uint16(paddingLen))
	copy(header[6:22], sourceAddress[:])
	binary.BigEndian.PutUint16(header[22:24], source.Port)
	// header[24:42] are 18 zero bytes
	clear(header[24:42])
	padding, err := randomUDPPadding(paddingLen)
	if err != nil {
		return err
	}
	out := buf.NewSize(len(header) + payloadLen + paddingLen)
	defer out.Release()
	common.Must1(out.Write(header[:]))
	common.Must1(out.Write(buffer.Bytes()))
	if paddingLen > 0 {
		common.Must1(out.Write(padding))
	}
	return u.writeFlush(out.Bytes())
}
