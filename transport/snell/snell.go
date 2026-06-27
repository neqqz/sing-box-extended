package snell

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

const (
	Version1            = 1
	Version2            = 2
	Version3            = 3
	Version4            = 4
	Version5            = 5
	DefaultSnellVersion = Version1

	// max packet length
	maxLength = 0x3FFF
)

const (
	CommandPing       byte = 0
	CommandConnect    byte = 1
	CommandConnectV2  byte = 5
	CommandUDP        byte = 6
	CommandUDPForward byte = 1

	CommandTunnel byte = 0
	CommandPong   byte = 1
	CommandError  byte = 2

	Version byte = 1
)

// Snell wraps an encrypted stream and handles the snell reply header.
type Snell struct {
	net.Conn
	buffer [1]byte
	reply  bool
}

func (s *Snell) Read(b []byte) (int, error) {
	if err := s.ReadReply(); err != nil {
		return 0, err
	}
	return s.Conn.Read(b)
}

func (s *Snell) ReadReply() error {
	if s.reply {
		return nil
	}
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	s.reply = true
	if s.buffer[0] == CommandTunnel {
		return nil
	} else if s.buffer[0] != CommandError {
		return errors.New("command not support")
	}
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	errcode := int(s.buffer[0])
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	length := int(s.buffer[0])
	msg := make([]byte, length)
	if _, err := io.ReadFull(s.Conn, msg); err != nil {
		return err
	}
	return fmt.Errorf("server reported code: %d, message: %s", errcode, string(msg))
}

func WriteHeader(conn net.Conn, host string, port uint, version int) error {
	return WriteHeaderWithReuse(conn, host, port, version, false)
}

func WriteHeaderWithReuse(conn net.Conn, host string, port uint, version int, reuse bool) error {
	buffer := &bytes.Buffer{}
	buffer.WriteByte(Version)
	if version == Version2 || reuse {
		buffer.WriteByte(CommandConnectV2)
	} else {
		buffer.WriteByte(CommandConnect)
	}
	buffer.WriteByte(0)
	buffer.WriteByte(uint8(len(host)))
	buffer.WriteString(host)
	binary.Write(buffer, binary.BigEndian, uint16(port))
	if _, err := conn.Write(buffer.Bytes()); err != nil {
		return err
	}
	return nil
}

func WriteUDPHeader(conn net.Conn, version int) error {
	if version < Version3 {
		return errors.New("unsupport UDP version")
	}
	_, err := conn.Write([]byte{Version, CommandUDP, 0x00})
	return err
}

// HalfClose only works after the request negotiated the reuse command.
func HalfClose(conn net.Conn) error {
	if err := writeZeroChunk(conn); err != nil {
		return err
	}
	if s, ok := conn.(*Snell); ok {
		s.reply = false
	}
	return nil
}

// StreamConn wraps a raw connection with the snell stream cipher for the given version.
func StreamConn(conn net.Conn, psk []byte, version int) *Snell {
	if version >= Version4 {
		return &Snell{Conn: newV4Conn(conn, psk)}
	}
	var cipher Cipher
	if version != Version1 {
		cipher = NewAES128GCM(psk)
	} else {
		cipher = NewChacha20Poly1305(psk)
	}
	return &Snell{Conn: newAEADConn(conn, cipher)}
}

// ServerStreamConn wraps a raw connection on the server side.
func ServerStreamConn(conn net.Conn, psk []byte, version int) *Snell {
	stream := StreamConn(conn, psk, version)
	stream.reply = true
	return stream
}

func PacketConn(conn net.Conn) net.PacketConn {
	return &packetConn{
		Conn: conn,
	}
}

func (s *Snell) WritePacketFrame(b []byte) (int, error) {
	if fw, ok := s.Conn.(packetFrameWriter); ok {
		return fw.WritePacketFrame(b)
	}
	return s.Conn.Write(b)
}

func WritePacket(w io.Writer, target, payload []byte) (int, error) {
	maxPayloadLength := maxLength - udpRequestHeaderLength(target)
	if maxPayloadLength <= 0 {
		return 0, errors.New("snell UDP address too large")
	}
	if len(payload) <= maxPayloadLength {
		return writePacket(w, target, payload)
	}
	return 0, errors.New("snell UDP payload too large")
}

func WritePacketResponse(w io.Writer, addr net.Addr, payload []byte) (int, error) {
	buffer := &bytes.Buffer{}
	target := parseAddrToSocksAddr(addr)
	if len(target) == 0 {
		return 0, errors.New("snell UDP response address invalid")
	}
	switch target[0] {
	case atypIPv4:
		if len(target) < 1+net.IPv4len+2 {
			return 0, errors.New("snell UDP response address invalid")
		}
		buffer.WriteByte(0x04)
		buffer.Write(target[1 : 1+net.IPv4len+2])
	case atypIPv6:
		if len(target) < 1+net.IPv6len+2 {
			return 0, errors.New("snell UDP response address invalid")
		}
		buffer.WriteByte(0x06)
		buffer.Write(target[1 : 1+net.IPv6len+2])
	default:
		return 0, errors.New("snell UDP response address invalid")
	}
	buffer.Write(payload)
	var err error
	if fw, ok := w.(packetFrameWriter); ok {
		_, err = fw.WritePacketFrame(buffer.Bytes())
	} else {
		_, err = w.Write(buffer.Bytes())
	}
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// UDPRequest is a parsed snell UDP forward request.
type UDPRequest struct {
	Host    string
	Ip      netip.Addr
	Port    uint16
	Payload []byte
}

func ParseUDPRequest(packet []byte) (UDPRequest, error) {
	if len(packet) < 2 || packet[0] != CommandUDPForward {
		return UDPRequest{}, errors.New("snell invalid UDP request")
	}
	if hostLen := int(packet[1]); hostLen != 0 {
		if len(packet) <= 2+hostLen+2 {
			return UDPRequest{}, errors.New("snell invalid UDP domain request")
		}
		offset := 2 + hostLen
		return UDPRequest{
			Host:    string(packet[2:offset]),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	}
	if len(packet) < 3 {
		return UDPRequest{}, errors.New("snell invalid UDP IP request")
	}
	switch packet[2] {
	case 0x04:
		if len(packet) < 3+net.IPv4len+2 {
			return UDPRequest{}, errors.New("snell invalid UDP IPv4 request")
		}
		offset := 3 + net.IPv4len
		ip, _ := netip.AddrFromSlice(packet[3:offset])
		return UDPRequest{
			Ip:      ip.Unmap(),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	case 0x06:
		if len(packet) < 3+net.IPv6len+2 {
			return UDPRequest{}, errors.New("snell invalid UDP IPv6 request")
		}
		offset := 3 + net.IPv6len
		ip, _ := netip.AddrFromSlice(packet[3:offset])
		return UDPRequest{
			Ip:      ip.Unmap(),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	default:
		return UDPRequest{}, errors.New("snell invalid UDP address type")
	}
}

func ReadPacket(r io.Reader, payload []byte) (net.Addr, int, error) {
	b := buf.Get(buf.UDPBufferSize)
	defer buf.Put(b)
	n, err := r.Read(b)
	headLen := 1
	if err != nil {
		return nil, 0, err
	}
	if n < headLen {
		return nil, 0, errors.New("insufficient UDP length")
	}
	switch b[0] {
	case 0x04:
		headLen += net.IPv4len + 2
		if n < headLen {
			err = errors.New("insufficient UDP length")
			break
		}
		b[0] = atypIPv4
	case 0x06:
		headLen += net.IPv6len + 2
		if n < headLen {
			err = errors.New("insufficient UDP length")
			break
		}
		b[0] = atypIPv6
	default:
		err = errors.New("ip version invalid")
	}
	if err != nil {
		return nil, 0, err
	}
	addr := splitSocksAddr(b[0:])
	if addr == nil {
		return nil, 0, errors.New("remote address invalid")
	}
	uAddr := addr.UDPAddr()
	if uAddr == nil {
		return nil, 0, errors.New("parse addr error")
	}
	length := len(payload)
	if n-headLen < length {
		length = n - headLen
	}
	copy(payload[:], b[headLen:headLen+length])
	return uAddr, length, nil
}

var endSignal = []byte{}

type packetFrameWriter interface {
	WritePacketFrame([]byte) (int, error)
}

func writeZeroChunk(conn net.Conn) error {
	if _, err := conn.Write(endSignal); err != nil {
		return err
	}
	return nil
}

func writePacket(w io.Writer, target, payload []byte) (int, error) {
	buffer := &bytes.Buffer{}
	buffer.WriteByte(CommandUDPForward)
	switch target[0] {
	case atypDomainName:
		hostLen := target[1]
		if len(target) < 1+1+int(hostLen)+2 {
			return 0, errors.New("snell UDP address invalid")
		}
		buffer.Write(target[1 : 1+1+hostLen+2])
	case atypIPv4:
		if len(target) < 1+net.IPv4len+2 {
			return 0, errors.New("snell UDP address invalid")
		}
		buffer.Write([]byte{0x00, 0x04})
		buffer.Write(target[1 : 1+net.IPv4len+2])
	case atypIPv6:
		if len(target) < 1+net.IPv6len+2 {
			return 0, errors.New("snell UDP address invalid")
		}
		buffer.Write([]byte{0x00, 0x06})
		buffer.Write(target[1 : 1+net.IPv6len+2])
	default:
		return 0, errors.New("snell UDP address invalid")
	}
	buffer.Write(payload)
	if fw, ok := w.(packetFrameWriter); ok {
		_, err := fw.WritePacketFrame(buffer.Bytes())
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	_, err := w.Write(buffer.Bytes())
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func udpRequestHeaderLength(target []byte) int {
	if len(target) == 0 {
		return maxLength + 1
	}
	switch target[0] {
	case atypDomainName:
		if len(target) < 2 {
			return maxLength + 1
		}
		return 1 + 1 + int(target[1]) + 2
	case atypIPv4:
		return 1 + 2 + net.IPv4len + 2
	case atypIPv6:
		return 1 + 2 + net.IPv6len + 2
	default:
		return maxLength + 1
	}
}

type packetConn struct {
	net.Conn
	rMux sync.Mutex
	wMux sync.Mutex
}

func (pc *packetConn) WritePacketFrame(b []byte) (int, error) {
	if s, ok := pc.Conn.(*Snell); ok {
		if fw, ok := s.Conn.(packetFrameWriter); ok {
			return fw.WritePacketFrame(b)
		}
	}
	return pc.Conn.Write(b)
}

func (pc *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	pc.wMux.Lock()
	defer pc.wMux.Unlock()
	return WritePacket(pc, parseAddrToSocksAddr(addr), b)
}

func (pc *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.rMux.Lock()
	defer pc.rMux.Unlock()
	addr, n, err := ReadPacket(pc.Conn, b)
	if err != nil {
		return 0, nil, err
	}
	return n, addr, nil
}
