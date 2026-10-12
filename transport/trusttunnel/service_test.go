package trusttunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
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
	if !s.isRateLimited("1.2.3.4", "u") {
		t.Fatal("3 failures must trigger the limit")
	}
	if s.isRateLimited("5.6.7.8", "u") {
		t.Fatal("limit must be per IP")
	}
}

func TestRateLimitSharedNAT(t *testing.T) {
	s := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP(), AuthMaxFailures: 3})
	s.UpdateUsers(map[string]string{"alice": "a", "bob": "b"})
	do := func(auth string) int {
		r := httptest.NewRequest(http.MethodConnect, "https://x", nil)
		r.RemoteAddr = "10.0.0.1:1"
		r.Header.Set("Proxy-Authorization", auth)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 5; i++ {
		do(buildAuth("alice", "wrong"))
	}
	if !s.isRateLimited("10.0.0.1", "alice") {
		t.Fatal("alice must be limited")
	}
	if s.isRateLimited("10.0.0.1", "bob") {
		t.Fatal("bob behind the same NAT must not be locked out")
	}
	// Rotating usernames must still hit the per-IP cap.
	for i := 0; i < 40; i++ {
		do(buildAuth("x"+strconv.Itoa(i), "wrong"))
	}
	if !s.isRateLimited("10.0.0.1", "bob") {
		t.Fatal("per-IP cap must stop username rotation")
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
	s.trackConn("gone", a)
	s.UpdateUsers(map[string]string{})
	if !a.closed || len(s.conns) != 0 {
		t.Fatal("conns of removed users must be dropped")
	}
}

type fakeCloser struct{ closed bool }

func (f *fakeCloser) Close() error { f.closed = true; return nil }
