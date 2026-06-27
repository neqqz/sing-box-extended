package openvpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/tls"
)

const (
	defaultHandshakeTimeout = 30 * time.Second
	controlRetransmitDelay  = time.Second
)

type Client struct {
	config    *ClientConfig
	tlsConfig tls.Config
	mux       *PacketMux

	control *ControlChannel
	tlsConn tls.Conn
	data    *DataChannel
	push    *PushReply

	cancel context.CancelFunc

	lastReceiveNano atomic.Int64
}

func NewClient(config *ClientConfig, io PacketIO, tlsConfig tls.Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("nil openvpn client config")
	}
	if io == nil {
		return nil, errors.New("nil openvpn packet io")
	}
	if tlsConfig == nil {
		return nil, errors.New("nil openvpn tls config")
	}
	var crypt ControlCrypt
	var err error
	if config.TLSAuthKey != nil {
		crypt, err = NewTLSAuth(config.TLSAuthKey, config.KeyDirection, config.Auth)
		if err != nil {
			return nil, err
		}
	} else if config.TLSCryptKey != nil {
		crypt, err = NewTLSCrypt(config.TLSCryptKey, true)
		if err != nil {
			return nil, err
		}
	}
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	mux := NewPacketMux(io)
	go mux.Run(runCtx)
	return &Client{
		config:    config,
		tlsConfig: tlsConfig,
		mux:       mux,
		control:   NewControlChannel(mux, crypt, local),
		cancel:    cancel,
	}, nil
}

func (c *Client) Handshake(ctx context.Context) (*PushReply, error) {
	if c == nil {
		return nil, errors.New("nil openvpn client")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHandshakeTimeout)
		defer cancel()
	}
	if c.config.TLSCryptV2WKc != nil {
		if err := c.sendResetV3(ctx); err != nil {
			return nil, fmt.Errorf("send hard reset v3: %w", err)
		}
	} else {
		if err := c.control.SendReset(ctx); err != nil {
			return nil, fmt.Errorf("send hard reset: %w", err)
		}
	}
	if err := c.waitServerReset(ctx); err != nil {
		return nil, err
	}

	controlConn := NewControlConn(c.control)
	tlsConn, err := c.tlsConfig.Client(controlConn)
	if err != nil {
		return nil, fmt.Errorf("openvpn tls client: %w", err)
	}
	c.tlsConn = tlsConn
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("openvpn tls handshake: %w", err)
	}

	clientRecord, err := NewClientKeyMethod2Record(
		InstallScriptOptionsString(c.config.Proto, c.config.Cipher, c.config.Auth),
		InstallScriptPeerInfo(c.config.Cipher),
		strings.TrimSpace(c.config.Username),
		c.config.Password,
	)
	if err != nil {
		return nil, err
	}
	clientBytes, err := clientRecord.MarshalClient()
	if err != nil {
		return nil, err
	}
	if _, err := c.tlsConn.Write(clientBytes); err != nil {
		return nil, fmt.Errorf("write key method 2 client record: %w", err)
	}
	serverRecord, err := c.readServerKeyMethod(ctx)
	if err != nil {
		return nil, err
	}

	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	keys, err := DeriveClientKeyMaterial(sources, c.control.LocalSessionID(), c.control.RemoteSessionID(), 32)
	if err != nil {
		return nil, fmt.Errorf("derive data channel keys: %w", err)
	}
	if _, err := c.tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
		return nil, fmt.Errorf("write push request: %w", err)
	}
	push, err := c.readPushReply(ctx)
	if err != nil {
		return nil, err
	}
	c.push = push
	dataCipher := c.config.Cipher
	if push.Cipher != "" {
		dataCipher = push.Cipher
	}
	if dataCipher == "" {
		return nil, errors.New("openvpn server did not negotiate a cipher and no cipher configured")
	}
	keyLen := CipherKeyLength(dataCipher)
	keys.SendCipherKey = keys.SendCipherKey[:keyLen]
	keys.RecvCipherKey = keys.RecvCipherKey[:keyLen]
	var cipher DataCipher
	if IsAEAD(dataCipher) {
		cipher, err = NewAEADCipher(keys, dataCipher)
	} else {
		cipher, err = NewCBCCipher(keys, c.config.Auth)
	}
	if err != nil {
		return nil, err
	}
	c.data = NewDataChannel(cipher, push.PeerID, push.CompLZO)
	c.markReceive()
	return push, nil
}

func (c *Client) WriteIPPacket(ctx context.Context, packet []byte) error {
	if c.data == nil {
		return errors.New("openvpn data channel is not ready")
	}
	encrypted, err := c.data.Encrypt(packet)
	if err != nil {
		return err
	}
	return c.mux.WritePacket(ctx, encrypted)
}

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	if c.data == nil {
		return nil, errors.New("openvpn data channel is not ready")
	}
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			return nil, err
		}
		plain, err := c.data.Decrypt(packet)
		if err != nil {
			continue
		}
		c.markReceive()
		return plain, nil
	}
}

func (c *Client) SinceReceive() time.Duration {
	return time.Duration(int64(time.Since(clientStart)) - c.lastReceiveNano.Load())
}

func (c *Client) markReceive() {
	c.lastReceiveNano.Store(int64(time.Since(clientStart)))
}

var clientStart = time.Now().Add(-time.Hour)

func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.tlsConn != nil {
		_ = c.tlsConn.Close()
	}
	if c.mux != nil {
		return c.mux.Close()
	}
	return nil
}

func (c *Client) waitServerReset(ctx context.Context) error {
	retransmits := 0
	for {
		readCtx := ctx
		cancel := func() {}
		if c.config.Proto == ProtoUDP {
			readCtx, cancel = context.WithTimeout(ctx, controlRetransmitDelay)
		}
		packet, err := c.control.Read(readCtx)
		cancel()
		if err != nil {
			if c.config.Proto == ProtoUDP && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				if err := c.control.RetransmitPending(ctx); err != nil {
					return fmt.Errorf("retransmit hard reset: %w", err)
				}
				retransmits++
				continue
			}
			return fmt.Errorf("read hard reset response after %d retransmits: %w", retransmits, err)
		}
		switch packet.Opcode {
		case PControlHardResetServerV2:
			return c.control.SendAck(ctx)
		case PControlHardResetServerV1:
			return fmt.Errorf("openvpn server replied with unsupported key method 1 reset")
		}
	}
}

func (c *Client) readServerKeyMethod(ctx context.Context) (*KeyMethod2Record, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			return nil, fmt.Errorf("read key method 2 server record: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		record, err := ParseServerKeyMethod2Record(buf)
		if err == nil {
			return record, nil
		}
		if !strings.Contains(err.Error(), "truncated") && !errors.Is(err, ioStringEOF) {
			return nil, err
		}
	}
}

func (c *Client) readPushReply(ctx context.Context) (*PushReply, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				break
			}
			return nil, fmt.Errorf("read push reply: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		if bytes.Contains(buf, []byte("\x00")) || strings.Contains(string(buf), "PUSH_REPLY") {
			msg := string(buf)
			if idx := strings.IndexByte(msg, 0); idx >= 0 {
				msg = msg[:idx]
			}
			if reply, err := ParsePushReply(msg); err == nil {
				return reply, nil
			}
		}
	}
	return nil, ctx.Err()
}

func (c *Client) sendResetV3(ctx context.Context) error {
	c.control.mu.Lock()
	messageID := c.control.sendMessage
	c.control.sendMessage++
	packet := &ControlPacket{
		Opcode:       PControlHardResetClientV3,
		KeyID:        c.control.keyID,
		LocalSession: c.control.local,
		MessageID:    messageID,
	}
	c.control.pending[messageID] = packet
	c.control.mu.Unlock()
	encoded, err := c.control.encodeAndWrap(ctx, packet)
	if err != nil {
		return err
	}
	encoded = append(encoded, c.config.TLSCryptV2WKc...)
	return c.control.io.WritePacket(ctx, encoded)
}

var _ net.Conn = (*ControlConn)(nil)
