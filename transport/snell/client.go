package snell

import (
	"context"
	"net"
	"strconv"
	"time"

	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ClientOptions struct {
	Dialer   N.Dialer
	Server   M.Socksaddr
	PSK      []byte
	Version  int
	Reuse    bool
	ObfsMode string
	ObfsHost string
}

type Client struct {
	dialer   N.Dialer
	server   M.Socksaddr
	psk      []byte
	version  int
	reuse    bool
	obfsMode string
	obfsHost string
	pool     *Pool
}

func NewClient(options ClientOptions) *Client {
	c := &Client{
		dialer:   options.Dialer,
		server:   options.Server,
		psk:      options.PSK,
		version:  options.Version,
		reuse:    options.Reuse,
		obfsMode: options.ObfsMode,
		obfsHost: options.ObfsHost,
	}
	if c.reuse {
		c.pool = NewPool(func(ctx context.Context) (*Snell, error) {
			conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
			if err != nil {
				return nil, err
			}
			return c.streamConn(conn), nil
		})
	}
	return c
}

func (c *Client) streamConn(conn net.Conn) *Snell {
	switch c.obfsMode {
	case "tls":
		conn = obfs.NewTLSObfs(conn, c.obfsHost)
	case "http":
		conn = obfs.NewHTTPObfs(conn, c.obfsHost, strconv.Itoa(int(c.server.Port)))
	}
	return StreamConn(conn, c.psk, c.version)
}

func (c *Client) writeHeader(ctx context.Context, conn net.Conn, destination M.Socksaddr, udp bool) (err error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
		defer conn.SetWriteDeadline(time.Time{})
	}
	if udp {
		err = WriteUDPHeader(conn, c.version)
		if err == nil && c.version >= Version4 {
			if sc, ok := conn.(*Snell); ok {
				err = sc.ReadReply()
			}
		}
		return
	}
	err = WriteHeaderWithReuse(conn, destination.AddrString(), uint(destination.Port), c.version, c.reuse)
	return
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if c.reuse {
		conn, err := c.pool.Get()
		if err != nil {
			return nil, err
		}
		if err = c.writeHeader(ctx, conn, destination, false); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	stream := c.streamConn(conn)
	if err = c.writeHeader(ctx, stream, destination, false); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stream, nil
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	stream := c.streamConn(conn)
	if err = c.writeHeader(ctx, stream, destination, true); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return PacketConn(stream), nil
}
