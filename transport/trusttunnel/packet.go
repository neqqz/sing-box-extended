package trusttunnel

import (
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

var (
	_ N.NetPacketConn = (*clientPacketConn)(nil)
	_ N.FrontHeadroom = (*clientPacketConn)(nil)
	_ N.NetPacketConn = (*serverPacketConn)(nil)
	_ N.FrontHeadroom = (*serverPacketConn)(nil)
)

type clientPacketConn struct {
	httpConn
	readMtx    sync.Mutex
	paddingMin int
	paddingMax int
	appName    string
}

func (u *clientPacketConn) FrontHeadroom() int {
	return 41 + u.paddingMax
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

func (u *clientPacketConn) readPacketFromServer(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	u.readMtx.Lock()
	defer u.readMtx.Unlock()

	u.mtx.Lock()
	if u.closed || u.body == nil {
		u.mtx.Unlock()
		return destination, net.ErrClosed
	}
	body := u.body
	u.mtx.Unlock()

	var header [40]byte
	_, err = io.ReadFull(body, header[:])
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header[0:4])
	if length < 36 {
		return destination, E.New("invalid trusttunnel packet length: ", length)
	}

	var srcIP [16]byte
	copy(srcIP[:], header[4:20])
	destination.Addr = parse16BytesIP(srcIP)
	destination.Port = binary.BigEndian.Uint16(header[20:22])

	payloadLen := int(length) - 36
	if payloadLen < 0 || payloadLen > math.MaxUint16 {
		return destination, E.New("invalid trusttunnel payload length: ", payloadLen)
	}

	if buffer.FreeLen() < payloadLen {
		if skipErr := rw.SkipN(body, payloadLen); skipErr != nil {
			return destination, skipErr
		}
		return destination, io.ErrShortBuffer
	}

	_, err = buffer.ReadFullFrom(body, payloadLen)
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

	var appBytes []byte
	if u.paddingMax > 0 {
		padLen := randomUDPPaddingLength(u.paddingMin, u.paddingMax)
		if padLen > 255 {
			padLen = 255
		}
		if padLen > 0 {
			appBytes = randomASCII(padLen)
		}
	} else if u.appName != "" {
		if len(u.appName) <= 255 {
			appBytes = []byte(u.appName)
		} else {
			appBytes = []byte(u.appName[:255])
		}
	}
	appLen := len(appBytes)

	headerLen := 41 + appLen
	lengthField := uint32(37 + appLen + payloadLen)
	destIP := buildPaddingIP(destination.Addr)

	if buffer.Start() >= headerLen {
		h := buffer.ExtendHeader(headerLen)
		binary.BigEndian.PutUint32(h[0:4], lengthField)
		clear(h[4:20])                          // Src IP = 0
		binary.BigEndian.PutUint16(h[20:22], 0) // Src Port = 0
		copy(h[22:38], destIP[:])               // Dst IP
		binary.BigEndian.PutUint16(h[38:40], destination.Port)
		h[40] = uint8(appLen)
		if appLen > 0 {
			copy(h[41:41+appLen], appBytes)
		}
		return u.writeChunks(buffer.Bytes())
	}

	var fixedHeader [41]byte
	binary.BigEndian.PutUint32(fixedHeader[0:4], lengthField)
	// fixedHeader[4:22] is zero
	copy(fixedHeader[22:38], destIP[:])
	binary.BigEndian.PutUint16(fixedHeader[38:40], destination.Port)
	fixedHeader[40] = uint8(appLen)

	if appLen > 0 {
		return u.writeChunks(fixedHeader[:], appBytes, buffer.Bytes())
	}
	return u.writeChunks(fixedHeader[:], buffer.Bytes())
}

type serverPacketConn struct {
	httpConn
	readMtx sync.Mutex
}

func (u *serverPacketConn) FrontHeadroom() int {
	return 40
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
	u.readMtx.Lock()
	defer u.readMtx.Unlock()

	u.mtx.Lock()
	if u.closed || u.body == nil {
		u.mtx.Unlock()
		return destination, net.ErrClosed
	}
	body := u.body
	u.mtx.Unlock()

	var header [41]byte
	_, err = io.ReadFull(body, header[:])
	if err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header[0:4])
	appLen := int(header[40])
	if length < uint32(37+appLen) {
		return destination, E.New("invalid trusttunnel packet length: ", length)
	}

	var dstIP [16]byte
	copy(dstIP[:], header[22:38])
	destination.Addr = parse16BytesIP(dstIP)
	destination.Port = binary.BigEndian.Uint16(header[38:40])

	if appLen > 0 {
		err = rw.SkipN(body, appLen)
		if err != nil {
			return destination, err
		}
	}

	payloadLen := int(length) - 37 - appLen
	if payloadLen < 0 || payloadLen > math.MaxUint16 {
		return destination, E.New("invalid trusttunnel payload length: ", payloadLen)
	}

	if buffer.FreeLen() < payloadLen {
		if skipErr := rw.SkipN(body, payloadLen); skipErr != nil {
			return destination, skipErr
		}
		return destination, io.ErrShortBuffer
	}

	_, err = buffer.ReadFullFrom(body, payloadLen)
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

	const headerLen = 40
	lengthField := uint32(36 + payloadLen)
	srcIP := buildPaddingIP(source.Addr)

	if buffer.Start() >= headerLen {
		h := buffer.ExtendHeader(headerLen)
		binary.BigEndian.PutUint32(h[0:4], lengthField)
		copy(h[4:20], srcIP[:])
		binary.BigEndian.PutUint16(h[20:22], source.Port)
		clear(h[22:38])                         // Dst IP = 0
		binary.BigEndian.PutUint16(h[38:40], 0) // Dst Port = 0
		return u.writeChunks(buffer.Bytes())
	}

	var header [headerLen]byte
	binary.BigEndian.PutUint32(header[0:4], lengthField)
	copy(header[4:20], srcIP[:])
	binary.BigEndian.PutUint16(header[20:22], source.Port)
	// header[22:40] is zero
	return u.writeChunks(header[:], buffer.Bytes())
}
