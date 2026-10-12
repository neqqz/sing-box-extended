package trusttunnel

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

func TestHTTPConnDeadlineUnsupported(t *testing.T) {
	var c httpConn
	if err := c.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("SetDeadline must return os.ErrInvalid so sing-box wraps the conn")
	}
	if !c.NeedAdditionalReadDeadline() {
		t.Fatal("NeedAdditionalReadDeadline must be true")
	}
}
