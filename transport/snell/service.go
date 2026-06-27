package snell

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type Handler interface {
	NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, clientID string)

	NewPacketConnection(ctx context.Context, conn net.PacketConn, source M.Socksaddr, clientID string)
}

type ServiceOptions struct {
	PSK      []byte
	Version  int
	ObfsMode string
	UDP      bool
	Logger   logger.ContextLogger
	Handler  Handler
}

type Service struct {
	psk      []byte
	version  int
	obfsMode string
	udp      bool
	logger   logger.ContextLogger
	handler  Handler
}

func NewService(options ServiceOptions) (*Service, error) {
	version := options.Version
	if version == 0 {
		version = Version4
	}
	if version != Version4 && version != Version5 {
		return nil, fmt.Errorf("snell inbound version %d is not supported", version)
	}
	if len(options.PSK) == 0 {
		return nil, errors.New("snell inbound requires psk")
	}
	switch options.ObfsMode {
	case "", "http", "tls":
	default:
		return nil, fmt.Errorf("snell inbound obfs mode error: %s", options.ObfsMode)
	}
	return &Service{
		psk:      options.PSK,
		version:  version,
		obfsMode: options.ObfsMode,
		udp:      options.UDP,
		logger:   options.Logger,
		handler:  options.Handler,
	}, nil
}

func (s *Service) NewConnection(ctx context.Context, rawConn net.Conn, source M.Socksaddr) error {
	conn := rawConn
	switch s.obfsMode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	}
	stream := ServerStreamConn(conn, s.psk, s.version)
	for {
		reuse, err := s.handleRequest(ctx, stream, source)
		if err != nil || !reuse {
			return err
		}
	}
}

func (s *Service) handleRequest(ctx context.Context, stream *Snell, source M.Socksaddr) (bool, error) {
	br := bufio.NewReader(stream)
	version, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if version != Version {
		return false, fmt.Errorf("snell invalid protocol version: %d", version)
	}
	command, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if command == CommandPing {
		_, _ = stream.Write([]byte{CommandPong})
		return false, nil
	}
	clientID, err := readClientID(br)
	if err != nil {
		return false, err
	}
	switch command {
	case CommandConnect, CommandConnectV2:
		return s.handleTCP(ctx, stream, br, command == CommandConnectV2, clientID, source)
	case CommandUDP:
		if !s.udp {
			return false, errors.New("snell UDP is disabled")
		}
		return false, s.handleUDP(ctx, stream, clientID, source)
	default:
		return false, fmt.Errorf("snell unknown command: %d", command)
	}
}

func (s *Service) handleTCP(ctx context.Context, stream *Snell, br *bufio.Reader, reuse bool, clientID string, source M.Socksaddr) (bool, error) {
	hostLen, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, errors.New("snell connect host is empty")
	}
	hostBytes := make([]byte, int(hostLen))
	if _, err := io.ReadFull(br, hostBytes); err != nil {
		return false, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return false, err
	}
	destination := M.ParseSocksaddrHostPort(string(hostBytes), binary.BigEndian.Uint16(portBytes[:]))
	conn := &tcpRequestConn{
		Conn:   stream,
		reader: br,
		reuse:  reuse,
	}
	s.handler.NewConnection(ctx, conn, source, destination, clientID)
	if !reuse {
		return false, nil
	}
	return true, nil
}

func (s *Service) handleUDP(ctx context.Context, stream *Snell, clientID string, source M.Socksaddr) error {
	if _, err := stream.Write([]byte{CommandTunnel}); err != nil {
		return err
	}
	pc := &serverPacketConn{
		conn:    stream,
		writeMu: &sync.Mutex{},
	}
	s.handler.NewPacketConnection(ctx, pc, source, clientID)
	return nil
}

const maxPacketLength = 0x3fff

func readClientID(r *bufio.Reader) (string, error) {
	length, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	id := make([]byte, int(length))
	if _, err := io.ReadFull(r, id); err != nil {
		return "", err
	}
	return string(id), nil
}

func writeCommandError(w io.Writer, code byte, message string) error {
	msg := []byte(message)
	if len(msg) > 255 {
		msg = msg[:255]
	}
	buf := make([]byte, 0, 3+len(msg))
	buf = append(buf, CommandError, code, byte(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

type tcpRequestConn struct {
	net.Conn
	reader       *bufio.Reader
	reuse        bool
	writeMu      sync.Mutex
	closeOnce    sync.Once
	replyWritten bool
}

func (c *tcpRequestConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if errors.Is(err, ErrZeroChunk) {
		err = io.EOF
	}
	return n, err
}

func (c *tcpRequestConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.replyWritten {
		payload := make([]byte, 1+len(p))
		payload[0] = CommandTunnel
		copy(payload[1:], p)
		if _, err := c.Conn.Write(payload); err != nil {
			return 0, err
		}
		c.replyWritten = true
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *tcpRequestConn) CloseWrite() error {
	return c.Close()
}

func (c *tcpRequestConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		if !c.replyWritten {
			err = writeCommandError(c.Conn, 0x65, "Remote EOF")
			if !c.reuse {
				err = errors.Join(err, c.Conn.Close())
			}
			return
		}
		if c.reuse {
			_, err = c.Conn.Write(nil)
			return
		}
		err = c.Conn.Close()
	})
	return err
}

type serverPacketConn struct {
	conn    *Snell
	writeMu *sync.Mutex
	readBuf []byte
}

func (c *serverPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readBuf == nil {
		c.readBuf = make([]byte, maxPacketLength)
	}
	for {
		n, err := c.conn.Read(c.readBuf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrZeroChunk) {
				return 0, nil, io.EOF
			}
			return 0, nil, err
		}
		request, err := ParseUDPRequest(c.readBuf[:n])
		if err != nil {
			return 0, nil, err
		}
		var destination M.Socksaddr
		if request.Ip.IsValid() {
			destination = M.SocksaddrFrom(request.Ip, request.Port)
		} else {
			destination = M.ParseSocksaddrHostPort(request.Host, request.Port)
		}
		length := copy(p, request.Payload)
		if destination.IsFqdn() {
			return length, destination, nil
		}
		return length, destination.UDPAddr(), nil
	}
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WritePacketResponse(c.conn, addr, p)
}

func (c *serverPacketConn) Close() error                       { return c.conn.Close() }
func (c *serverPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *serverPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *serverPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *serverPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
