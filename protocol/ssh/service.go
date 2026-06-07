package ssh

import (
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/ssh"
)

type Service interface {
	PasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)
	PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
	UpdateUsers(users []option.SSHUser)
	Handle(ctx context.Context, serverConn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, metadata adapter.InboundContext, user string)
	Close() error
}

var _ Service = (*service)(nil)

type service struct {
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	users    []option.SSHUser
	mtx      sync.RWMutex
}

func newService(router adapter.ConnectionRouterEx, logger logger.ContextLogger, users []option.SSHUser) *service {
	return &service{
		router: router,
		logger: logger,
		users:  users,
	}
}

func (h *service) PasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	h.mtx.RLock()
	users := h.users
	h.mtx.RUnlock()
	for _, user := range users {
		if user.Name != "" && user.Name != conn.User() {
			continue
		}
		if user.Password != "" && user.Password == string(password) {
			return &ssh.Permissions{Extensions: map[string]string{"user": user.Name}}, nil
		}
	}
	return nil, E.New("password authentication failed for user ", conn.User())
}

func (h *service) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	h.mtx.RLock()
	users := h.users
	h.mtx.RUnlock()
	for _, user := range users {
		if user.Name != "" && user.Name != conn.User() {
			continue
		}
		for _, authorizedKey := range user.AuthorizedKeys {
			parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
			if err != nil {
				continue
			}
			if bytes.Equal(parsed.Marshal(), key.Marshal()) {
				return &ssh.Permissions{Extensions: map[string]string{"user": user.Name}}, nil
			}
		}
	}
	return nil, E.New("public key authentication failed for user ", conn.User())
}

func (h *service) UpdateUsers(users []option.SSHUser) {
	h.mtx.Lock()
	h.users = users
	h.mtx.Unlock()
}

func (h *service) Handle(ctx context.Context, serverConn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, metadata adapter.InboundContext, user string) {
	h.logger.InfoContext(ctx, "[", user, "] authenticated SSH connection from ", metadata.Source)
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			go h.handleDirectChannel(ctx, metadata, newChannel)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
		}
	}
}

func (h *service) Close() error {
	return nil
}

func (h *service) handleDirectChannel(ctx context.Context, metadata adapter.InboundContext, newChannel ssh.NewChannel) {
	var payload directTCPIPData
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		h.logger.ErrorContext(ctx, E.Cause(err, "parse direct-tcpip payload"))
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		h.logger.ErrorContext(ctx, E.Cause(err, "accept direct-tcpip channel"))
		return
	}
	go ssh.DiscardRequests(requests)
	connMetadata := metadata
	connMetadata.Destination = M.ParseSocksaddrHostPort(payload.HostToConnect, uint16(payload.PortToConnect))
	conn := deadline.NewConn(&channelConn{
		Channel:    channel,
		localAddr:  metadata.OriginDestination.TCPAddr(),
		remoteAddr: metadata.Source.TCPAddr(),
	})
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", connMetadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, connMetadata, N.OnceClose(func(it error) {
		channel.Close()
	}))
}

type directTCPIPData struct {
	HostToConnect     string
	PortToConnect     uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

type channelConn struct {
	ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *channelConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *channelConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *channelConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *channelConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *channelConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}
