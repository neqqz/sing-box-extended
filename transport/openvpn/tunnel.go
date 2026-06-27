package openvpn

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/tls"
)

type TunnelOptions struct {
	System         bool
	Name           string
	CreateDialer   func(interfaceName string) N.Dialer
	Dialer         N.Dialer
	Servers        []option.ServerOptions
	TLSConfig      tls.Config
	Config         *ClientConfig
	AllowedAddress []netip.Prefix
	UDPTimeout     time.Duration
	ReconnectDelay time.Duration
	PingInterval   time.Duration
	PingRestart    time.Duration
}

type Tunnel struct {
	ctx         context.Context
	cancel      context.CancelFunc
	logger      logger.ContextLogger
	options     TunnelOptions
	device      Device
	client      *Client
	mtu         uint32
	serverIndex int
	wg          sync.WaitGroup

	await chan struct{}
	mu    sync.Mutex
}

func NewTunnel(ctx context.Context, logger logger.ContextLogger, options TunnelOptions) (*Tunnel, error) {
	if options.ReconnectDelay == 0 {
		options.ReconnectDelay = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Tunnel{
		ctx:     ctx,
		cancel:  cancel,
		logger:  logger,
		options: options,
		await:   make(chan struct{}),
	}, nil
}

func (t *Tunnel) Start() error {
	go func() {
		client, err := t.getClient()
		if err != nil {
			t.logger.Error("OpenVPN connect: ", err)
			close(t.await)
			return
		}
		t.mtu = 1500
		if client.push.MTU > 0 {
			t.mtu = client.push.MTU
		}
		deviceOptions := DeviceOptions{
			Context:        t.ctx,
			Logger:         t.logger,
			System:         t.options.System,
			UDPTimeout:     t.options.UDPTimeout,
			CreateDialer:   t.options.CreateDialer,
			Name:           t.options.Name,
			MTU:            t.mtu,
			Address:        client.push.Prefixes,
			AllowedAddress: t.options.AllowedAddress,
		}
		device, err := NewDevice(deviceOptions)
		if err != nil {
			client.Close()
			t.logger.Error("create OpenVPN device: ", err)
			close(t.await)
			return
		}
		t.device = device
		if err := device.Start(); err != nil {
			client.Close()
			t.logger.Error("start OpenVPN device: ", err)
			close(t.await)
			return
		}
		close(t.await)
		t.maintainTunnel()
	}()
	return nil
}

func (t *Tunnel) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := t.isTunnelInitialized(ctx); err != nil {
		return nil, err
	}
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return t.device.DialContext(ctx, network, destination)
}

func (t *Tunnel) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := t.isTunnelInitialized(ctx); err != nil {
		return nil, err
	}
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return t.device.ListenPacket(ctx, destination)
}

func (t *Tunnel) Close() error {
	t.cancel()
	t.mu.Lock()
	if t.client != nil {
		t.client.Close()
		t.client = nil
	}
	if t.device != nil {
		t.device.Close()
		t.device = nil
	}
	t.mu.Unlock()
	t.wg.Wait()
	return nil
}

func (t *Tunnel) isTunnelInitialized(ctx context.Context) error {
	select {
	case <-t.await:
	case <-ctx.Done():
		return ctx.Err()
	}
	if t.device == nil {
		return E.New("endpoint not initialized")
	}
	return nil
}

func (t *Tunnel) maintainTunnel() {
	t.wg.Add(2)
	go func() {
		defer t.wg.Done()
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, t.mtu)
		sizes := make([]int, 1)
		for t.ctx.Err() == nil {
			_, err := t.device.Read(bufs, sizes, 0)
			if err != nil {
				if t.ctx.Err() != nil {
					return
				}
				continue
			}
			client, err := t.getClient()
			if err != nil {
				return
			}
			if err := client.WriteIPPacket(t.ctx, bufs[0][:sizes[0]]); err != nil {
				if t.ctx.Err() != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer t.wg.Done()
		for t.ctx.Err() == nil {
			client, err := t.getClient()
			if err != nil {
				return
			}
			packet, err := client.ReadIPPacket(t.ctx)
			if err != nil {
				if t.ctx.Err() != nil {
					return
				}
				if ok := t.closeClient(client); ok {
					t.logger.ErrorContext(t.ctx, fmt.Errorf("connection lost: %v", err))
				}
				continue
			}
			if bytes.Equal(packet, pingPayload) {
				continue
			}
			if t.ctx.Err() != nil {
				return
			}
			if t.ctx.Err() != nil {
				return
			}
			if _, err := t.device.Write([][]byte{packet}, 0); err != nil {
				return
			}
		}
	}()
	pingInterval := t.options.PingInterval
	if pingInterval == 0 && t.client != nil && t.client.push.Ping > 0 {
		pingInterval = time.Duration(t.client.push.Ping) * time.Second
	}
	if pingInterval > 0 {
		go func() {
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-t.ctx.Done():
					return
				case <-ticker.C:
					client, err := t.getClient()
					if err != nil {
						return
					}
					client.WriteIPPacket(t.ctx, pingPayload)
				}
			}
		}()
	}
	pingRestart := t.options.PingRestart
	if pingRestart == 0 && t.client != nil && t.client.push.PingRestart > 0 {
		pingRestart = time.Duration(t.client.push.PingRestart) * time.Second
	}
	if pingRestart > 0 {
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			ticker := time.NewTicker(pingRestart)
			defer ticker.Stop()
			for {
				select {
				case <-t.ctx.Done():
					return
				case <-ticker.C:
					client, err := t.getClient()
					if err != nil {
						return
					}
					if client.SinceReceive() >= pingRestart {
						if ok := t.closeClient(client); ok {
							t.logger.ErrorContext(t.ctx, fmt.Errorf("ping-restart timeout: no packet received for %s", pingRestart))
						}
					}
				}
			}
		}()
	}
	<-t.ctx.Done()
}

func (t *Tunnel) getClient() (*Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}
	if t.client != nil {
		return t.client, nil
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		t.logger.NoticeContext(t.ctx, "connecting to OpenVPN server")
		client, err := t.connect()
		if err != nil {
			t.logger.ErrorContext(t.ctx, fmt.Errorf("connect failed: %v", err))
			timer.Reset(t.options.ReconnectDelay)
			select {
			case <-t.ctx.Done():
				return nil, t.ctx.Err()
			case <-timer.C:
			}
			continue
		}
		t.client = client
		t.logger.NoticeContext(t.ctx, "connected to OpenVPN server")
		return client, nil
	}
}

func (t *Tunnel) closeClient(client *Client) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if client == t.client {
		t.client.Close()
		t.client = nil
		return true
	}
	return false
}

func (t *Tunnel) connect() (*Client, error) {
	config := t.options.Config
	server := t.options.Servers[t.serverIndex].Build()
	t.serverIndex = (t.serverIndex + 1) % len(t.options.Servers)
	connectCtx, cancel := context.WithTimeout(t.ctx, t.options.ReconnectDelay)
	defer cancel()
	var conn net.Conn
	var err error
	if config.Proto == ProtoTCP {
		conn, err = t.options.Dialer.DialContext(connectCtx, N.NetworkTCP, server)
	} else {
		conn, err = t.options.Dialer.DialContext(connectCtx, N.NetworkUDP, server)
	}
	if err != nil {
		return nil, fmt.Errorf("dial openvpn server: %w", err)
	}
	var packetIO PacketIO
	if config.Proto == ProtoTCP {
		packetIO = NewTCPPacketIO(conn)
	} else {
		packetIO = NewDatagramPacketIO(conn)
	}
	client, err := NewClient(config, packetIO, t.options.TLSConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_, err = client.Handshake(connectCtx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("openvpn handshake: %w", err)
	}
	return client, nil
}

var pingPayload = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}
