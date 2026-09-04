package main

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func findFreePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port
}

// TestTrustTunnel runs e2e tests with combinations of:
// - Transport: H2, QUIC
// - Congestion controllers (QUIC only): bbr, cubic, reno
// - Multiplex: enabled/disabled
// - Network: tcp-only, tcp+udp
func TestTrustTunnel(t *testing.T) {
	type combo struct {
		name                 string
		quic                 bool
		congestionController string
		multiplex            bool
		network              option.NetworkList
		testUDP              bool
	}

	var combos []combo

	// H2 transport combos
	for _, mux := range []bool{false, true} {
		for _, net := range []struct {
			name    string
			list    option.NetworkList
			testUDP bool
		}{
			{"tcp", option.NetworkList(N.NetworkTCP), false},
			{"tcp+udp", option.NetworkList(N.NetworkTCP + "\n" + N.NetworkUDP), true},
		} {
			name := fmt.Sprintf("h2/mux=%v/%s", mux, net.name)
			combos = append(combos, combo{
				name:      name,
				quic:      false,
				multiplex: mux,
				network:   net.list,
				testUDP:   net.testUDP,
			})
		}
	}

	// QUIC transport combos (requires UDP in network for HTTP/3 listener)
	congestionControllers := []string{"bbr", "cubic", "reno"}
	for _, cc := range congestionControllers {
		for _, mux := range []bool{false, true} {
			name := fmt.Sprintf("quic/%s/mux=%v", cc, mux)
			combos = append(combos, combo{
				name:                 name,
				quic:                 true,
				congestionController: cc,
				multiplex:            mux,
				network:              option.NetworkList(N.NetworkTCP + "\n" + N.NetworkUDP),
				testUDP:              true,
			})
		}
	}

	for _, c := range combos {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			testTrustTunnelCombo(t, c.quic, c.congestionController, c.multiplex, c.network, c.testUDP)
		})
	}
}

func testTrustTunnelCombo(t *testing.T, useQUIC bool, cc string, multiplex bool, network option.NetworkList, testUDP bool) {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")

	srvPort := findFreePort(t)
	cliPort := findFreePort(t)
	tstPort := findFreePort(t)

	var muxOpts *option.TrustTunnelMultiplexOptions
	if multiplex {
		muxOpts = &option.TrustTunnelMultiplexOptions{
			Enabled:        true,
			MaxConnections: 4,
			MinStreams:     2,
		}
	}

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: cliPort,
					},
				},
			},
			{
				Type: C.TypeTrustTunnel,
				Tag:  "tt-in",
				Options: &option.TrustTunnelInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: srvPort,
					},
					Users: []option.TrustTunnelUser{{
						Name:     "testuser",
						Password: "testpass",
					}},
					Network:              network,
					CongestionController: cc,
					CWND:                 32,
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							ALPN:            badoption.Listable[string]{"h2", "h3"},
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
			},
			{
				Type: C.TypeTrustTunnel,
				Tag:  "tt-out",
				Options: &option.TrustTunnelOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: srvPort,
					},
					Username:             "testuser",
					Password:             "testpass",
					Network:              network,
					QUIC:                 useQUIC,
					CongestionController: cc,
					CWND:                 32,
					Multiplex:            muxOpts,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: "example.org",
							Insecure:   true,
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{"mixed-in"},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: "tt-out",
							},
						},
					},
				},
			},
		},
	})

	if testUDP {
		testSuit(t, cliPort, tstPort)
	} else {
		testTCP(t, cliPort, tstPort)
	}
}
