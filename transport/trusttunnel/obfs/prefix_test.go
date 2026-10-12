package obfs

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	sboxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common/logger"
)

type staticProvider struct{ set *sboxtls.RandomPrefixSet }

func (p staticProvider) Current() *sboxtls.RandomPrefixSet { return p.set }

func checkWith(t *testing.T, p sboxtls.RandomPrefix) (matched bool, wasClosed bool) {
	t.Helper()
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		_ = tls.Client(cli, &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"}).Handshake()
	}()
	checker := NewPrefixChecker(nil, staticProvider{&sboxtls.RandomPrefixSet{Prefixes: []sboxtls.RandomPrefix{p}}}, 0, "", 0, logger.NOP())
	conn, ok := checker.Check(srv)
	if ok {
		return true, false
	}
	_ = conn
	_ = srv.SetReadDeadline(time.Now().Add(time.Second))
	_, err := srv.Read(make([]byte, 1))
	return false, err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

func TestPrefixCheckerMatchAndMismatch(t *testing.T) {
	if m, _ := checkWith(t, sboxtls.RandomPrefix{Prefix: []byte{0}, Mask: []byte{0}}); !m {
		t.Fatal("zero-mask prefix must match any ClientHello")
	}
	m, closed := checkWith(t, sboxtls.RandomPrefix{Prefix: []byte("\xff\xff\xff\xff\xff\xff\xff\xff")})
	if m || !closed {
		t.Fatalf("mismatch must drop the connection without fallback: matched=%v closed=%v", m, closed)
	}
}

func TestPublicOnly(t *testing.T) {
	for addr, wantErr := range map[string]bool{
		"127.0.0.1:443": true, "10.0.0.1:443": true, "192.168.1.1:443": true,
		"169.254.169.254:80": true, "[::1]:443": true, "[::ffff:127.0.0.1]:443": true,
		"8.8.8.8:443": false,
	} {
		if err := publicOnly("tcp", addr, nil); (err != nil) != wantErr {
			t.Errorf("%s: err=%v wantErr=%v", addr, err, wantErr)
		}
	}
}

func TestResolveFallbackPort(t *testing.T) {
	cases := []struct {
		name     string
		fallback string
		sniPort  int
		want     string
	}{
		{"nothing configured defaults to 443", "", 0, "443"},
		{"static fallback port is used by default (historical behaviour)", "x5.com:8443", 0, "8443"},
		{"explicit port wins over the static fallback port", "127.0.0.1:8444", 443, "443"},
		{"explicit port works without a static fallback", "", 8443, "8443"},
		{"unparsable static fallback falls back to 443", "not-a-hostport", 0, "443"},
	}
	for _, tc := range cases {
		if got := resolveFallbackPort(tc.fallback, tc.sniPort); got != tc.want {
			t.Errorf("%s: resolveFallbackPort(%q, %d) = %q, want %q", tc.name, tc.fallback, tc.sniPort, got, tc.want)
		}
	}
}
