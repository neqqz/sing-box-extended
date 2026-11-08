package trusttunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

func TestIPConversion(t *testing.T) {
	// IPv4 test
	v4 := netip.MustParseAddr("192.0.2.1")
	paddedV4 := buildPaddingIP(v4)
	for i := 0; i < 12; i++ {
		if paddedV4[i] != 0 {
			t.Fatalf("expected paddedV4[%d] to be 0, got %d", i, paddedV4[i])
		}
	}
	if !bytes.Equal(paddedV4[12:16], []byte{192, 0, 2, 1}) {
		t.Fatalf("expected paddedV4[12:16] to be 192.0.2.1, got %v", paddedV4[12:16])
	}
	parsedV4 := parse16BytesIP(paddedV4)
	if parsedV4 != v4 {
		t.Fatalf("expected parsedV4 to be %v, got %v", v4, parsedV4)
	}

	// IPv6 test
	v6 := netip.MustParseAddr("2001:db8::1")
	paddedV6 := buildPaddingIP(v6)
	parsedV6 := parse16BytesIP(paddedV6)
	if parsedV6 != v6 {
		t.Fatalf("expected parsedV6 to be %v, got %v", v6, parsedV6)
	}
}

func TestAuth(t *testing.T) {
	auth := buildAuth("testuser", "testpass")
	expected := "Basic dGVzdHVzZXI6dGVzdHBhc3M="
	if auth != expected {
		t.Fatalf("expected auth %s, got %s", expected, auth)
	}

	creds, ok := parseAuth(auth)
	if !ok || creds != "dGVzdHVzZXI6dGVzdHBhc3M=" {
		t.Fatalf("failed to parse auth: %s, ok: %v", creds, ok)
	}

	creds, ok = parseAuth("basic dGVzdHVzZXI6dGVzdHBhc3M=")
	if !ok || creds != "dGVzdHVzZXI6dGVzdHBhc3M=" {
		t.Fatalf("failed to parse lowercase basic auth: %s, ok: %v", creds, ok)
	}

	_, ok = parseAuth("Bearer sometoken")
	if ok {
		t.Fatalf("expected false for Bearer auth")
	}
}

func TestPacketFraming(t *testing.T) {
	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()

	client := &clientPacketConn{
		httpConn: httpConn{
			writer:  clientWriter,
			body:    clientReader,
			created: make(chan struct{}),
		},
		paddingMin: 10,
		paddingMax: 30,
	}
	close(client.created)

	server := &serverPacketConn{
		httpConn: httpConn{
			writer:  serverWriter,
			body:    serverReader,
			created: make(chan struct{}),
		},
	}
	close(server.created)

	// Client -> Server
	dest := M.ParseSocksaddr("1.2.3.4:53")
	payload := []byte("hello dns query payload")

	errChan := make(chan error, 1)
	go func() {
		b := buf.NewPacket()
		defer b.Release()
		b.Write(payload)
		errChan <- client.WritePacket(b, dest)
	}()

	recvBuf := buf.NewPacket()
	defer recvBuf.Release()
	readDest, err := server.ReadPacket(recvBuf)
	if err != nil {
		t.Fatalf("server.ReadPacket failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("client.WritePacket failed: %v", err)
	}
	if readDest.String() != dest.String() {
		t.Fatalf("expected dest %s, got %s", dest.String(), readDest.String())
	}
	if !bytes.Equal(recvBuf.Bytes(), payload) {
		t.Fatalf("expected payload %s, got %s", string(payload), string(recvBuf.Bytes()))
	}

	// Server -> Client
	src := M.ParseSocksaddr("1.2.3.4:53")
	responsePayload := []byte("dns response payload")

	go func() {
		b := buf.NewPacket()
		defer b.Release()
		b.Write(responsePayload)
		errChan <- server.WritePacket(b, src)
	}()

	recvClientBuf := buf.NewPacket()
	defer recvClientBuf.Release()
	readSrc, err := client.ReadPacket(recvClientBuf)
	if err != nil {
		t.Fatalf("client.ReadPacket failed: %v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("server.WritePacket failed: %v", err)
	}
	if readSrc.String() != src.String() {
		t.Fatalf("expected src %s, got %s", src.String(), readSrc.String())
	}
	if !bytes.Equal(recvClientBuf.Bytes(), responsePayload) {
		t.Fatalf("expected response %s, got %s", string(responsePayload), string(recvClientBuf.Bytes()))
	}
}

func TestServiceHTTP(t *testing.T) {
	service := NewService(ServiceOptions{})
	service.UpdateUsers(map[string]string{
		"alice": "secret123",
	})

	// 1. Unauthenticated request without fallback -> 404 Not Found (anti-probing)
	{
		req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
		req.Host = "example.com:443"
		rec := httptest.NewRecorder()
		service.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", rec.Code)
		}
	}

	// 2. Unauthenticated request with fallback -> handled by fallbackHandler
	{
		fallbackCalled := false
		fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fallbackCalled = true
			w.WriteHeader(http.StatusTeapot)
		})
		sWithFallback := NewService(ServiceOptions{
			FallbackHandler: fallback,
		})
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		rec := httptest.NewRecorder()
		sWithFallback.ServeHTTP(rec, req)
		if !fallbackCalled {
			t.Fatalf("expected fallback handler to be called")
		}
		if rec.Code != http.StatusTeapot {
			t.Fatalf("expected status 418 from fallback, got %d", rec.Code)
		}
	}

	// 3. Authenticated HealthCheck -> 200 OK
	{
		req := httptest.NewRequest(http.MethodConnect, "http://_check", nil)
		req.Host = "_check"
		req.Header.Set("Proxy-Authorization", buildAuth("alice", "secret123"))
		rec := httptest.NewRecorder()
		service.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200 for _check, got %d", rec.Code)
		}
	}

	// 4. Authenticated ICMP -> 501 Not Implemented
	{
		req := httptest.NewRequest(http.MethodConnect, "http://_icmp", nil)
		req.Host = "_icmp"
		req.Header.Set("Proxy-Authorization", buildAuth("alice", "secret123"))
		rec := httptest.NewRecorder()
		service.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("expected status 501 for _icmp, got %d", rec.Code)
		}
	}

	// 5. Authenticated non-CONNECT without fallback -> 404
	{
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Proxy-Authorization", buildAuth("alice", "secret123"))
		rec := httptest.NewRecorder()
		service.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected status 404 for GET without fallback, got %d", rec.Code)
		}
	}
}

type directDialer struct{}

func (d directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var stdDialer net.Dialer
	return stdDialer.DialContext(ctx, network, destination.String())
}

func (d directDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type echoHandler struct{}

func (e *echoHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
	return nil
}

func (e *echoHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	defer conn.Close()
	for {
		p := buf.New()
		dest, err := conn.ReadPacket(p)
		if err != nil {
			p.Release()
			return nil
		}
		resp := buf.New()
		resp.WriteString("pong: ")
		resp.Write(p.Bytes())
		p.Release()
		if err = conn.WritePacket(resp, dest); err != nil {
			return nil
		}
	}
}

func TestClientServerEndToEnd(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	h2Server := &http2.Server{}
	service := NewService(ServiceOptions{
		Handler: &echoHandler{},
	})
	service.UpdateUsers(map[string]string{
		"alice": "secret123",
	})
	defer service.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go h2Server.ServeConn(c, &http2.ServeConnOpts{
				Handler: service,
			})
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		Dialer:        directDialer{},
		Server:        M.ParseSocksaddr(l.Addr().String()),
		Username:      "alice",
		Password:      "secret123",
		UDPPaddingMin: 10,
		UDPPaddingMax: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// 1. HealthCheck
	if err := client.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	// 2. TCP CONNECT
	tcpConn, err := client.Dial(ctx, "echo.local:80")
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer tcpConn.Close()

	msg := []byte("hello trusttunnel tcp")
	if _, err := tcpConn.Write(msg); err != nil {
		t.Fatalf("tcp write failed: %v", err)
	}
	bufResp := make([]byte, len(msg))
	if _, err := io.ReadFull(tcpConn, bufResp); err != nil {
		t.Fatalf("tcp read failed: %v", err)
	}
	if !bytes.Equal(bufResp, msg) {
		t.Fatalf("expected tcp echo %s, got %s", string(msg), string(bufResp))
	}

	// 3. UDP CONNECT
	pktConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pktConn.Close()

	udpPktConn, ok := pktConn.(N.NetPacketConn)
	if !ok {
		t.Fatalf("expected NetPacketConn")
	}

	destAddr := M.ParseSocksaddr("192.0.2.1:53")
	udpPayload := []byte("hello udp")
	udpBuf := buf.New()
	udpBuf.Write(udpPayload)
	if err := udpPktConn.WritePacket(udpBuf, destAddr); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	recvBuf := buf.New()
	defer recvBuf.Release()
	recvDest, err := udpPktConn.ReadPacket(recvBuf)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}
	if recvDest.String() != destAddr.String() {
		t.Fatalf("expected dest %s, got %s", destAddr.String(), recvDest.String())
	}
	expectedPayload := "pong: hello udp"
	if string(recvBuf.Bytes()) != expectedPayload {
		t.Fatalf("expected udp reply %s, got %s", expectedPayload, string(recvBuf.Bytes()))
	}

	// 4. Bad credentials test -> expected 407
	badClient, err := NewClient(ctx, ClientOptions{
		Dialer:   directDialer{},
		Server:   M.ParseSocksaddr(l.Addr().String()),
		Username: "alice",
		Password: "wrongpassword",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer badClient.Close()

	err = badClient.HealthCheck(ctx)
	if err == nil {
		t.Fatalf("expected error for bad credentials, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("404")) {
		t.Fatalf("expected 404 error, got %v", err)
	}
}
