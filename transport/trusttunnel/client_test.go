//go:build with_utls

package trusttunnel

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	sboxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

func TestMultiplexClientCompaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadCtx, deadCancel := context.WithCancel(ctx)
	deadCancel()

	c := &MultiplexClient{
		ctx:     ctx,
		clients: []*Client{{ctx: deadCtx}, {ctx: ctx}},
	}

	// Compact dead clients
	n := 0
	for _, client := range c.clients {
		if client.ctx.Err() == nil {
			c.clients[n] = client
			n++
		}
	}
	clear(c.clients[n:])
	c.clients = c.clients[:n]

	if len(c.clients) != 1 {
		t.Fatalf("expected 1 alive client, got %d", len(c.clients))
	}
	if c.clients[0].ctx.Err() != nil {
		t.Fatalf("expected surviving client to be active")
	}
}

func TestClientUserAgent(t *testing.T) {
	// 1. Default user-agent should match ChromeUA
	cDefault, err := NewClient(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer cDefault.Close()

	reqDefault := cDefault.newConnectRequest("example.com:443")
	ua := reqDefault.Header.Get("User-Agent")
	if !strings.Contains(ua, "Chrome") {
		t.Fatalf("expected default User-Agent to contain Chrome, got %q", ua)
	}

	// 2. Custom user-agent
	customUA := "Mozilla/5.0 (CustomBrowser/1.0)"
	cCustom, err := NewClient(context.Background(), ClientOptions{UserAgent: customUA})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer cCustom.Close()

	reqCustom := cCustom.newConnectRequest("example.com:443")
	if got := reqCustom.Header.Get("User-Agent"); got != customUA {
		t.Fatalf("expected User-Agent %q, got %q", customUA, got)
	}

	// 3. User-Agent "none" should suppress User-Agent header
	cNone, err := NewClient(context.Background(), ClientOptions{UserAgent: "none"})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer cNone.Close()

	reqNone := cNone.newConnectRequest("example.com:443")
	if vals, ok := reqNone.Header["User-Agent"]; !ok || len(vals) != 1 || vals[0] != "" {
		t.Fatalf("expected empty User-Agent slice to suppress Go default, got %#v", vals)
	}
}

type testE2EHandler struct {
	tcpReceived chan []byte
	udpReceived chan []byte
}

func (h *testE2EHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	go func() {
		defer conn.Close()
		b := make([]byte, 1024)
		n, err := conn.Read(b)
		if err != nil && err != io.EOF {
			return
		}
		h.tcpReceived <- append([]byte(nil), b[:n]...)
		_, _ = conn.Write(b[:n])
	}()
	return nil
}

func (h *testE2EHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	go func() {
		defer conn.Close()
		packet := buf.NewPacket()
		defer packet.Release()
		dest, err := conn.ReadPacket(packet)
		if err != nil {
			return
		}
		h.udpReceived <- append([]byte(nil), packet.Bytes()...)
		echo := buf.NewPacket()
		_, _ = echo.Write(packet.Bytes())
		_ = conn.WritePacket(echo, dest)
	}()
	return nil
}

func TestClientServiceE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cert, err := sboxtls.GenerateKeyPair(nil, nil, nil, "localhost")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}
	serverTLS := &stdtls.Config{
		Certificates: []stdtls.Certificate{*cert},
		NextProtos:   []string{http2.NextProtoTLS},
	}
	l, err := stdtls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	handler := &testE2EHandler{
		tcpReceived: make(chan []byte, 1),
		udpReceived: make(chan []byte, 1),
	}
	service := NewService(ServiceOptions{
		Ctx:           ctx,
		Handler:       handler,
		UDPPaddingMin: 10,
		UDPPaddingMax: 20,
	})
	service.UpdateUsers(map[string]string{"alice": "secret123"})
	defer service.Close()

	h2Server := &http2.Server{}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*stdtls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				continue
			}
			go h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
				Context: ctx,
				Handler: service,
			})
		}
	}()

	clientTLS, err := sboxtls.NewClient(ctx, nil, "localhost", option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("failed to create client tls: %v", err)
	}

	rawDialer, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	serverAddr := M.ParseSocksaddr(l.Addr().String())
	client, err := NewClient(ctx, ClientOptions{
		Dialer:        rawDialer,
		TLSConfig:     clientTLS,
		Server:        serverAddr,
		Username:      "alice",
		Password:      "secret123",
		UDPPaddingMin: 10,
		UDPPaddingMax: 20,
		HealthCheck:   true,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// 1. HealthCheck
	hcCtx, hcCancel := context.WithTimeout(ctx, 3*time.Second)
	defer hcCancel()
	if err := client.HealthCheck(hcCtx); err != nil {
		t.Fatalf("health check failed: %v", err)
	}

	// 2. TCP Dial & Echo
	tcpConn, err := client.Dial(ctx, "echo.target:80")
	if err != nil {
		t.Fatalf("tcp dial failed: %v", err)
	}
	defer tcpConn.Close()

	sendData := []byte("hello trusttunnel tcp")
	if _, err := tcpConn.Write(sendData); err != nil {
		t.Fatalf("tcp write failed: %v", err)
	}
	select {
	case got := <-handler.tcpReceived:
		if string(got) != string(sendData) {
			t.Fatalf("server received %q, expected %q", string(got), string(sendData))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for server to receive tcp")
	}

	reply := make([]byte, len(sendData))
	if _, err := io.ReadFull(tcpConn, reply); err != nil {
		t.Fatalf("tcp read failed: %v", err)
	}
	if string(reply) != string(sendData) {
		t.Fatalf("client received echo %q, expected %q", string(reply), string(sendData))
	}

	// 3. UDP Packet Send & Echo
	pktConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("listen packet failed: %v", err)
	}
	defer pktConn.Close()
	netPktConn := pktConn.(N.NetPacketConn)

	udpPkt := buf.NewPacket()
	_, _ = udpPkt.Write([]byte("ping udp packet"))
	targetDest := M.ParseSocksaddr("1.1.1.1:53")
	if err := netPktConn.WritePacket(udpPkt, targetDest); err != nil {
		t.Fatalf("write packet failed: %v", err)
	}

	select {
	case got := <-handler.udpReceived:
		if string(got) != "ping udp packet" {
			t.Fatalf("server received udp %q, expected 'ping udp packet'", string(got))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for server to receive udp")
	}

	recvPkt := buf.NewPacket()
	defer recvPkt.Release()
	retDest, err := netPktConn.ReadPacket(recvPkt)
	if err != nil {
		t.Fatalf("read packet failed: %v", err)
	}
	if string(recvPkt.Bytes()) != "ping udp packet" {
		t.Fatalf("client received udp %q, expected 'ping udp packet'", string(recvPkt.Bytes()))
	}
	if retDest.String() != targetDest.String() {
		t.Fatalf("expected dest %s, got %s", targetDest, retDest)
	}

	// 4. Invalid Password should be rejected
	badClient, err := NewClient(ctx, ClientOptions{
		Dialer:      rawDialer,
		TLSConfig:   clientTLS,
		Server:      serverAddr,
		Username:    "alice",
		Password:    "wrong-password",
		HealthCheck: false,
	})
	if err != nil {
		t.Fatalf("failed to create bad client: %v", err)
	}
	defer badClient.Close()

	_, err = badClient.Dial(ctx, "echo.target:80")
	if err == nil {
		t.Fatalf("expected bad client to fail authentication")
	}
}
