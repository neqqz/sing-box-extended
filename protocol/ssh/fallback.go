package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/onclose"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/ssh"
)

var _ Service = (*Fallback)(nil)

type Fallback struct {
	Service
	ctx           context.Context
	logger        logger.ContextLogger
	dialer        N.Dialer
	serverAddr    M.Socksaddr
	clientVersion string
	mainSigner    ssh.Signer
	issueSigner   ssh.Signer
	hostKeys      []ssh.PublicKey
	keyAlgorithms []string
	pending       map[string]*upstreamConn
	mtx           sync.Mutex
}

type upstreamConn struct {
	conn     net.Conn
	client   ssh.Conn
	channels <-chan ssh.NewChannel
	requests <-chan *ssh.Request
}

func NewFallback(ctx context.Context, logger logger.ContextLogger, inner Service, options *option.SSHFallbackServerOptions) (*Fallback, error) {
	serverAddr := options.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 22
	}
	if !serverAddr.Addr.IsValid() && serverAddr.Fqdn == "" {
		return nil, E.New("missing upstream server address")
	}
	upstreamDialer, err := dialer.New(ctx, options.DialerOptions, serverAddr.IsFqdn())
	if err != nil {
		return nil, err
	}
	fallback := &Fallback{
		Service:       inner,
		ctx:           ctx,
		logger:        logger,
		dialer:        upstreamDialer,
		serverAddr:    serverAddr,
		clientVersion: options.ClientVersion,
		keyAlgorithms: options.HostKeyAlgorithms,
		pending:       make(map[string]*upstreamConn),
	}
	if fallback.clientVersion == "" {
		fallback.clientVersion = "SSH-2.0-OpenSSH_9.6"
	}
	if options.CA != nil {
		signer, err := parseCAKey(options.CA)
		if err != nil {
			return nil, E.Cause(err, "parse CA")
		}
		fallback.mainSigner = signer
	}
	if options.IssueCA != nil {
		signer, err := parseCAKey(options.IssueCA)
		if err != nil {
			return nil, E.Cause(err, "parse issue CA")
		}
		fallback.issueSigner = signer
	}
	if fallback.issueSigner == nil && fallback.mainSigner != nil {
		fallback.issueSigner = fallback.mainSigner
	}
	for _, hostKey := range options.HostKey {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
		if err != nil {
			return nil, E.New("parse upstream host key ", hostKey)
		}
		fallback.hostKeys = append(fallback.hostKeys, key)
	}
	for _, hostKeyPath := range options.HostKeyPath {
		content, err := os.ReadFile(os.ExpandEnv(hostKeyPath))
		if err != nil {
			return nil, E.Cause(err, "read upstream host key ", hostKeyPath)
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(content)
		if err != nil {
			return nil, E.Cause(err, "parse upstream host key ", hostKeyPath)
		}
		fallback.hostKeys = append(fallback.hostKeys, key)
	}
	return fallback, nil
}

func (f *Fallback) PasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if permissions, err := f.Service.PasswordCallback(conn, password); err == nil {
		return permissions, nil
	}
	if err := f.dial(string(conn.SessionID()), conn.User(), ssh.Password(string(password))); err != nil {
		return nil, E.Cause(err, "upstream authentication failed for user ", conn.User())
	}
	return &ssh.Permissions{Extensions: map[string]string{"user": conn.User(), "fallback": "1"}}, nil
}

func (f *Fallback) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if permissions, err := f.Service.PublicKeyCallback(conn, key); err == nil {
		return permissions, nil
	}
	if verifyCertificate(f.mainSigner, conn, key) {
		signer, err := issueCertificate(f.issueSigner, conn.User())
		if err != nil {
			return nil, E.Cause(err, "upstream authentication failed for user ", conn.User())
		}
		if err := f.dial(string(conn.SessionID()), conn.User(), ssh.PublicKeys(signer)); err != nil {
			return nil, E.Cause(err, "upstream authentication failed for user ", conn.User())
		}
		return &ssh.Permissions{Extensions: map[string]string{"user": conn.User(), "fallback": "1"}}, nil
	}
	return nil, E.New("public key authentication failed for user ", conn.User())
}

func (f *Fallback) Handle(ctx context.Context, serverConn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, metadata adapter.InboundContext, user string) {
	if serverConn.Permissions == nil || serverConn.Permissions.Extensions["fallback"] != "1" {
		f.Service.Handle(ctx, serverConn, channels, requests, metadata, user)
		return
	}
	sessionID := string(serverConn.SessionID())
	f.mtx.Lock()
	upstream := f.pending[sessionID]
	delete(f.pending, sessionID)
	f.mtx.Unlock()
	if upstream == nil {
		serverConn.Close()
		return
	}
	f.logger.InfoContext(ctx, "[", user, "] forwarded SSH connection from ", metadata.Source)
	go proxyDownstreamRequests(requests, upstream.client)
	go proxyGlobalRequests(upstream.requests, serverConn)
	go func() {
		for newChannel := range upstream.channels {
			go proxyChannel(newChannel, serverConn)
		}
	}()
	var wg sync.WaitGroup
	for newChannel := range channels {
		wg.Go(func() {
			proxyChannel(newChannel, upstream.client)
		})
	}
	wg.Wait()
	upstream.client.Close()
	upstream.conn.Close()
	serverConn.Close()
}

func (f *Fallback) Close() error {
	f.mtx.Lock()
	connections := make([]net.Conn, 0, len(f.pending))
	for id, upstream := range f.pending {
		if upstream != nil {
			connections = append(connections, upstream.conn)
		}
		delete(f.pending, id)
	}
	f.mtx.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	return f.Service.Close()
}

func (f *Fallback) dial(sessionID string, user string, auth ssh.AuthMethod) error {
	f.mtx.Lock()
	if _, attempted := f.pending[sessionID]; attempted {
		f.mtx.Unlock()
		return E.New("fallback already attempted")
	}
	f.pending[sessionID] = nil
	f.mtx.Unlock()
	conn, err := f.dialer.DialContext(f.ctx, N.NetworkTCP, f.serverAddr)
	if err != nil {
		f.mtx.Lock()
		delete(f.pending, sessionID)
		f.mtx.Unlock()
		return err
	}
	conn = onclose.NewConn(conn, func() {
		f.mtx.Lock()
		delete(f.pending, sessionID)
		f.mtx.Unlock()
	})
	config := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{auth},
		ClientVersion:     f.clientVersion,
		HostKeyAlgorithms: f.keyAlgorithms,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(f.hostKeys) == 0 {
				return nil
			}
			serverKey := key.Marshal()
			for _, hostKey := range f.hostKeys {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}
			return E.New("upstream host key mismatch, server sent ", key.Type(), " ", base64.StdEncoding.EncodeToString(serverKey))
		},
		Timeout: C.TCPTimeout,
	}
	client, channels, requests, err := ssh.NewClientConn(conn, f.serverAddr.String(), config)
	if err != nil {
		conn.Close()
		return err
	}
	f.mtx.Lock()
	f.pending[sessionID] = &upstreamConn{conn: conn, client: client, channels: channels, requests: requests}
	f.mtx.Unlock()
	return nil
}

func proxyChannel(newChannel ssh.NewChannel, target ssh.Conn) {
	targetChannel, targetRequests, err := target.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		if openErr, ok := err.(*ssh.OpenChannelError); ok {
			newChannel.Reject(openErr.Reason, openErr.Message)
		} else {
			newChannel.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}
	sourceChannel, sourceRequests, err := newChannel.Accept()
	if err != nil {
		targetChannel.Close()
		return
	}
	go proxyChannelRequests(sourceRequests, targetChannel)
	go io.Copy(targetChannel.Stderr(), sourceChannel.Stderr())
	go io.Copy(sourceChannel.Stderr(), targetChannel.Stderr())
	go func() {
		io.Copy(targetChannel, sourceChannel)
		targetChannel.CloseWrite()
	}()
	go func() {
		io.Copy(sourceChannel, targetChannel)
		sourceChannel.CloseWrite()
	}()
	proxyChannelRequests(targetRequests, sourceChannel)
	sourceChannel.Close()
	targetChannel.Close()
}

func proxyGlobalRequests(requests <-chan *ssh.Request, target ssh.Conn) {
	for request := range requests {
		if request.Type == "hostkeys-00@openssh.com" {
			if request.WantReply {
				request.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := target.SendRequest(request.Type, request.WantReply, request.Payload)
		if request.WantReply {
			if err != nil {
				request.Reply(false, nil)
			} else {
				request.Reply(ok, payload)
			}
		}
	}
}

func proxyDownstreamRequests(requests <-chan *ssh.Request, target ssh.Conn) {
	for request := range requests {
		switch request.Type {
		case "no-more-sessions@openssh.com", "hostkeys-prove-00@openssh.com":
			if request.WantReply {
				request.Reply(false, nil)
			}
			continue
		}
		ok, payload, err := target.SendRequest(request.Type, request.WantReply, request.Payload)
		if request.WantReply {
			if err != nil {
				request.Reply(false, nil)
			} else {
				request.Reply(ok, payload)
			}
		}
	}
}

func proxyChannelRequests(requests <-chan *ssh.Request, target ssh.Channel) {
	for request := range requests {
		ok, err := target.SendRequest(request.Type, request.WantReply, request.Payload)
		if request.WantReply {
			if err != nil {
				request.Reply(false, nil)
			} else {
				request.Reply(ok, nil)
			}
		}
	}
}


