//go:build with_openvpn && with_gvisor

// OpenVPN E2E tests. Require a local OpenVPN server setup.
//
// Setup (run once before testing):
//
//   # Generate PKI
//   mkdir -p /tmp/ovpn-e2e/pki/{issued,private}
//   cd /tmp/ovpn-e2e/pki
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 1 -nodes -keyout ca.key -out ca.crt -subj "/CN=E2ETestCA"
//   openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout private/server.key -out server.csr -subj "/CN=server"
//   openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out issued/server.crt -days 1
//   openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout private/client.key -out client.csr -subj "/CN=client"
//   openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out issued/client.crt -days 1
//   openvpn --genkey secret ta.key
//   openvpn --genkey secret ta-auth.key
//
//   # Start servers (4 instances: TCP/UDP × tls-crypt/tls-auth)
//   # TCP + tls-crypt on :11940, subnet 10.99.0.0/24
//   # UDP + tls-crypt on :11941, subnet 10.99.1.0/24
//   # TCP + tls-auth  on :11942, subnet 10.99.2.0/24
//   # UDP + tls-auth  on :11943, subnet 10.99.3.0/24
//   #
//   # Each server config needs: topology subnet, duplicate-cn, persist-tun,
//   # data-ciphers AES-256-GCM:AES-128-GCM:AES-192-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC:AES-192-CBC
//   # auth SHA256, keepalive 10 60, ca/cert/key from above PKI.
//   # tls-auth servers use: tls-auth ta-auth.key 0
//   # tls-crypt servers use: tls-crypt ta.key
//   sudo openvpn --config /tmp/ovpn-e2e/server-tcp-crypt.conf --daemon
//   sudo openvpn --config /tmp/ovpn-e2e/server-udp-crypt.conf --daemon
//   sudo openvpn --config /tmp/ovpn-e2e/server-tcp-auth.conf --daemon
//   sudo openvpn --config /tmp/ovpn-e2e/server-udp-auth.conf --daemon
//
//   # Start HTTP servers on each VPN subnet
//   for ip in 10.99.0.1 10.99.1.1 10.99.2.1 10.99.3.1; do
//     mkdir -p /tmp/ovpn-e2e/$ip && echo "hello" > /tmp/ovpn-e2e/$ip/index.html
//     cd /tmp/ovpn-e2e/$ip && python3 -m http.server 8080 --bind $ip &
//   done
//
// Run tests:
//
//   go test -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_masque,with_mtproxy,with_manager,with_admin_panel,with_v2ray_api,with_ccm,with_ocm,with_profiler,with_openvpn,with_sudoku,with_trusttunnel" \
//     -run TestE2E -v -count=1 ./transport/openvpn/ -timeout 300s
//
// Tests all 28 combinations: 2 protos (tcp/udp) × 2 TLS modes (tls-crypt/tls-auth) × 7 ciphers.

package openvpn_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Servers (started externally):
//   TCP+tls-crypt :11940  subnet 10.99.0.0/24
//   UDP+tls-crypt :11941  subnet 10.99.1.0/24
//   TCP+tls-auth  :11942  subnet 10.99.2.0/24
//   UDP+tls-auth  :11943  subnet 10.99.3.0/24
//   TCP+plain     :11944  subnet 10.99.4.0/24
//   UDP+plain     :11945  subnet 10.99.5.0/24
//   TCP+tls-crypt+SHA1  :11946  subnet 10.99.6.0/24  (CBC only)
//   TCP+tls-crypt+SHA512 :11947 subnet 10.99.7.0/24  (CBC only)
// Each has HTTP on .1:8080 serving "hello"

const pkiDir = "/tmp/ovpn-e2e/pki"

type serverConfig struct {
	proto    string
	port     uint16
	tlsMode  string // "tls-crypt" or "tls-auth"
	httpAddr string
}

var servers = []serverConfig{
	{"tcp", 11940, "tls-crypt", "10.99.0.1:8080"},
	{"udp", 11941, "tls-crypt", "10.99.1.1:8080"},
	{"tcp", 11942, "tls-auth", "10.99.2.1:8080"},
	{"udp", 11943, "tls-auth", "10.99.3.1:8080"},
}

var ciphers = []string{
	"AES-128-GCM",
	"AES-192-GCM",
	"AES-256-GCM",
	"CHACHA20-POLY1305",
	"AES-128-CBC",
	"AES-192-CBC",
	"AES-256-CBC",
}

var portCounter atomic.Uint32

func init() { portCounter.Store(18100) }

func nextPort() uint16 { return uint16(portCounter.Add(1)) }

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("PKI not found: %v", err)
	}
	return string(data)
}

func testCombo(t *testing.T, srv serverConfig, cipher string) {
	t.Helper()
	ca := readFile(t, pkiDir+"/ca.crt")
	cert := readFile(t, pkiDir+"/issued/client.crt")
	key := readFile(t, pkiDir+"/private/client.key")

	ovpnOpts := &option.OpenVPNOutboundOptions{
		Servers: []option.ServerOptions{{Server: "127.0.0.1", ServerPort: srv.port}},
		Proto:   srv.proto,
		Cipher:  cipher,
		Auth:    "SHA256",
		OpenVPNOutboundTLSOptionsContainer: option.OpenVPNOutboundTLSOptionsContainer{
			TLS: &option.OpenVPNTLSOptions{CA: ca, Certificate: cert, Key: key},
		},
	}

	switch srv.tlsMode {
	case "tls-crypt":
		ovpnOpts.TLSCrypt = readFile(t, pkiDir+"/ta.key")
	case "tls-auth":
		ovpnOpts.TLSAuth = readFile(t, pkiDir+"/ta-auth.key")
		ovpnOpts.KeyDirection = 1
	}

	port := nextPort()
	opts := option.Options{
		Log: &option.LogOptions{Level: "error"},
		Inbounds: []option.Inbound{{
			Type: "socks",
			Options: &option.SocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     (*badoption.Addr)(&badoption.Addr{}),
					ListenPort: port,
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: "openvpn", Tag: "vpn", Options: ovpnOpts}},
		Route:     &option.RouteOptions{Final: "vpn"},
	}

	ctx := include.Context(context.Background())
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()

	time.Sleep(2 * time.Second)

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", port), socks.Version5, "", "")
	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(srv.httpAddr))
	if err != nil {
		t.Fatal("dial:", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("GET /index.html HTTP/1.0\r\nHost: test\r\n\r\n"))
	if err != nil {
		t.Fatal("write:", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal("read:", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Fatalf("no 'hello' in response: %s", string(body)[:min(len(body), 200)])
	}
}

// 4 servers × 7 ciphers = 28 combinations
func TestE2E(t *testing.T) {
	for _, srv := range servers {
		for _, cipher := range ciphers {
			name := fmt.Sprintf("%s/%s/%s", srv.proto, srv.tlsMode, cipher)
			srv, cipher := srv, cipher
			t.Run(name, func(t *testing.T) {
				testCombo(t, srv, cipher)
			})
		}
	}
}

// Test CBC ciphers with different auth algorithms (SHA1, SHA512)
func TestE2E_Auth(t *testing.T) {
	type authServer struct {
		port     uint16
		auth     string
		httpAddr string
	}
	authServers := []authServer{
		{11946, "SHA1", "10.99.6.1:8080"},
		{11947, "SHA512", "10.99.7.1:8080"},
	}
	cbcCiphers := []string{"AES-128-CBC", "AES-256-CBC"}

	for _, as := range authServers {
		for _, cipher := range cbcCiphers {
			name := fmt.Sprintf("auth-%s/%s", as.auth, cipher)
			as, cipher := as, cipher
			t.Run(name, func(t *testing.T) {
				ca := readFile(t, pkiDir+"/ca.crt")
				cert := readFile(t, pkiDir+"/issued/client.crt")
				key := readFile(t, pkiDir+"/private/client.key")
				tlsCrypt := readFile(t, pkiDir+"/ta.key")
				port := nextPort()
				opts := option.Options{
					Log: &option.LogOptions{Level: "error"},
					Inbounds: []option.Inbound{{
						Type: "socks",
						Options: &option.SocksInboundOptions{
							ListenOptions: option.ListenOptions{
								Listen:     (*badoption.Addr)(&badoption.Addr{}),
								ListenPort: port,
							},
						},
					}},
					Outbounds: []option.Outbound{{
						Type: "openvpn", Tag: "vpn",
						Options: &option.OpenVPNOutboundOptions{
							Servers:  []option.ServerOptions{{Server: "127.0.0.1", ServerPort: as.port}},
							Proto:    "tcp",
							Cipher:   cipher,
							Auth:     as.auth,
							TLSCrypt: tlsCrypt,
							OpenVPNOutboundTLSOptionsContainer: option.OpenVPNOutboundTLSOptionsContainer{
								TLS: &option.OpenVPNTLSOptions{CA: ca, Certificate: cert, Key: key},
							},
						},
					}},
					Route: &option.RouteOptions{Final: "vpn"},
				}
				ctx := include.Context(context.Background())
				instance, err := box.New(box.Options{Context: ctx, Options: opts})
				if err != nil {
					t.Fatal(err)
				}
				if err := instance.Start(); err != nil {
					t.Fatal(err)
				}
				defer instance.Close()
				time.Sleep(2 * time.Second)
				doHTTPCheck(t, port, as.httpAddr)
			})
		}
	}
}

// Test tunnel stability with multiple sequential requests
func TestE2E_BulkData(t *testing.T) {
	ca := readFile(t, pkiDir+"/ca.crt")
	cert := readFile(t, pkiDir+"/issued/client.crt")
	key := readFile(t, pkiDir+"/private/client.key")
	tlsCrypt := readFile(t, pkiDir+"/ta.key")
	port := nextPort()
	opts := option.Options{
		Log: &option.LogOptions{Level: "error"},
		Inbounds: []option.Inbound{{
			Type: "socks",
			Options: &option.SocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     (*badoption.Addr)(&badoption.Addr{}),
					ListenPort: port,
				},
			},
		}},
		Outbounds: []option.Outbound{{
			Type: "openvpn", Tag: "vpn",
			Options: &option.OpenVPNOutboundOptions{
				Servers:  []option.ServerOptions{{Server: "127.0.0.1", ServerPort: 11940}},
				Proto:    "tcp",
				Cipher:   "AES-256-GCM",
				Auth:     "SHA256",
				TLSCrypt: tlsCrypt,
				OpenVPNOutboundTLSOptionsContainer: option.OpenVPNOutboundTLSOptionsContainer{
					TLS: &option.OpenVPNTLSOptions{CA: ca, Certificate: cert, Key: key},
				},
			},
		}},
		Route: &option.RouteOptions{Final: "vpn"},
	}
	ctx := include.Context(context.Background())
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	time.Sleep(2 * time.Second)

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", port), socks.Version5, "", "")
	for i := 0; i < 10; i++ {
		conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr("10.99.0.1:8080"))
		if err != nil {
			t.Fatalf("request %d dial: %v", i, err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "GET /index.html HTTP/1.0\r\nHost: test\r\n\r\n")
		body, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			t.Fatalf("request %d read: %v", i, err)
		}
		if !strings.Contains(string(body), "hello") {
			t.Fatalf("request %d: no 'hello'", i)
		}
	}
}

func doHTTPCheck(t *testing.T, socksPort uint16, httpAddr string) {
	t.Helper()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(httpAddr))
	if err != nil {
		t.Fatal("dial:", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("GET /index.html HTTP/1.0\r\nHost: test\r\n\r\n"))
	if err != nil {
		t.Fatal("write:", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal("read:", err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Fatalf("no 'hello' in response: %s", string(body)[:min(len(body), 200)])
	}
}

func startInstance(t *testing.T, ovpnOpts *option.OpenVPNOutboundOptions) uint16 {
	t.Helper()
	port := nextPort()
	opts := option.Options{
		Log: &option.LogOptions{Level: "error"},
		Inbounds: []option.Inbound{{
			Type: "socks",
			Options: &option.SocksInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     (*badoption.Addr)(&badoption.Addr{}),
					ListenPort: port,
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: "openvpn", Tag: "vpn", Options: ovpnOpts}},
		Route:     &option.RouteOptions{Final: "vpn"},
	}
	ctx := include.Context(context.Background())
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	time.Sleep(2 * time.Second)
	return port
}

func TestE2E_CompLZO(t *testing.T) {
	ca := readFile(t, pkiDir+"/ca.crt")
	cert := readFile(t, pkiDir+"/issued/client.crt")
	key := readFile(t, pkiDir+"/private/client.key")
	tlsCrypt := readFile(t, pkiDir+"/ta.key")

	for _, cipher := range ciphers {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			port := startInstance(t, &option.OpenVPNOutboundOptions{
				Servers:  []option.ServerOptions{{Server: "127.0.0.1", ServerPort: 11948}},
				Proto:    "udp",
				Cipher:   cipher,
				Auth:     "SHA256",
				TLSCrypt: tlsCrypt,
				OpenVPNOutboundTLSOptionsContainer: option.OpenVPNOutboundTLSOptionsContainer{
					TLS: &option.OpenVPNTLSOptions{CA: ca, Certificate: cert, Key: key},
				},
			})
			doHTTPCheck(t, port, "10.99.8.1:8080")
		})
	}
}

func TestE2E_AES192(t *testing.T) {
	ca := readFile(t, pkiDir+"/ca.crt")
	cert := readFile(t, pkiDir+"/issued/client.crt")
	key := readFile(t, pkiDir+"/private/client.key")
	tlsCrypt := readFile(t, pkiDir+"/ta.key")

	type combo struct {
		proto    string
		port     uint16
		httpAddr string
	}
	for _, c := range []combo{
		{"tcp", 11940, "10.99.0.1:8080"},
		{"udp", 11941, "10.99.1.1:8080"},
	} {
		for _, cipher := range []string{"AES-192-GCM", "AES-192-CBC"} {
			c, cipher := c, cipher
			t.Run(fmt.Sprintf("%s/%s", c.proto, cipher), func(t *testing.T) {
				port := startInstance(t, &option.OpenVPNOutboundOptions{
					Servers:  []option.ServerOptions{{Server: "127.0.0.1", ServerPort: c.port}},
					Proto:    c.proto,
					Cipher:   cipher,
					Auth:     "SHA256",
					TLSCrypt: tlsCrypt,
					OpenVPNOutboundTLSOptionsContainer: option.OpenVPNOutboundTLSOptionsContainer{
						TLS: &option.OpenVPNTLSOptions{CA: ca, Certificate: cert, Key: key},
					},
				})
				doHTTPCheck(t, port, c.httpAddr)
			})
		}
	}
}

var _ net.Conn
