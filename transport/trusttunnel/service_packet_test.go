package trusttunnel

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestServiceRejectsBadAuthAndRateLimits(t *testing.T) {
	s := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP(), AuthRateLimit: time.Minute, AuthMaxFailures: 3})
	s.UpdateUsers(map[string]string{"u": "p"})
	do := func(auth string) int {
		r := httptest.NewRequest(http.MethodConnect, "https://x", nil)
		r.RemoteAddr = "1.2.3.4:5555"
		r.Header.Set("Proxy-Authorization", auth)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	bad := buildAuth("u", "wrong")
	for i := 0; i < 3; i++ {
		if code := do(bad); code != http.StatusNotFound {
			t.Fatalf("bad auth must look like a plain 404, got %d", code)
		}
	}
	if !s.isRateLimited("1.2.3.4") {
		t.Fatal("3 failures must trigger the limit")
	}
	if s.isRateLimited("5.6.7.8") {
		t.Fatal("limit must be per IP")
	}
}

func TestServiceUntrackConn(t *testing.T) {
	s := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP()})
	a, b := &fakeCloser{}, &fakeCloser{}
	s.trackConn("u", a)
	s.trackConn("u", b)
	s.untrackConn("u", a)
	if len(s.conns["u"]) != 1 {
		t.Fatal("untrack must remove exactly one conn")
	}
	s.untrackConn("u", b)
	if _, ok := s.conns["u"]; ok {
		t.Fatal("empty user entry must be removed")
	}
	// removed user: UpdateUsers closes its conns
	s.trackConn("gone", a)
	s.UpdateUsers(map[string]string{})
	if !a.closed || len(s.conns) != 0 {
		t.Fatal("conns of removed users must be dropped")
	}
}

func initConn(c *httpConn, body io.ReadCloser, w io.Writer) {
	c.writer, c.created = w, make(chan struct{})
	c.setup(body, nil)
}

type fakeCloser struct{ closed bool }

func (f *fakeCloser) Close() error { f.closed = true; return nil }

func TestUDPFrameRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	client := &clientPacketConn{paddingMin: 5, paddingMax: 9}
	initConn(&client.httpConn, io.NopCloser(&bytes.Buffer{}), &wire)
	payload := []byte("hello udp")
	dst := M.ParseSocksaddrHostPort("1.2.3.4", 53)
	if err := client.writePacketToServer(buf.As(append([]byte(nil), payload...)).ToOwned(), dst); err != nil {
		t.Fatal(err)
	}
	server := &serverPacketConn{}
	initConn(&server.httpConn, io.NopCloser(&wire), io.Discard)
	out := buf.NewPacket()
	defer out.Release()
	got, err := server.readPacketFromClient(out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr.String() != "1.2.3.4" || got.Port != 53 || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("frame mismatch: %v %q", got, out.Bytes())
	}
}

func TestUDPFrameLengthShorterThanHeaderIsError(t *testing.T) {
	// length=1 is smaller than the fixed part of the frame: must be an error, not a panic.
	frame := make([]byte, 4+2+16+2+16+2+1)
	frame[3] = 1
	server := &serverPacketConn{}
	initConn(&server.httpConn, io.NopCloser(bytes.NewReader(frame)), io.Discard)
	out := buf.NewPacket()
	defer out.Release()
	if _, err := server.readPacketFromClient(out); err == nil {
		t.Fatal("short length must be rejected")
	}
}

func TestValidatePadding(t *testing.T) {
	for _, c := range []struct {
		min, max, limit int
		ok              bool
	}{
		{0, 0, MaxDataPadding, true}, {10, 255, MaxDataPadding, true}, {0, 256, MaxDataPadding, false},
		{5, 4, MaxUDPPadding, false}, {-1, 3, MaxUDPPadding, false}, {0, 65536, MaxUDPPadding, false},
	} {
		if err := ValidatePadding("x", c.min, c.max, c.limit); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v", c, err)
		}
	}
}
