package trusttunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func TestBadAuthLooksLike404AndNeverLocksOut(t *testing.T) {
	s := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP()})
	s.UpdateUsers(map[string]string{"u": "p"})
	for i := 0; i < 200; i++ {
		r := httptest.NewRequest(http.MethodConnect, "https://x", nil)
		r.RemoteAddr = "1.2.3.4:5555"
		r.Header.Set("Proxy-Authorization", buildAuth("u", "wrong"))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("bad auth must look like a plain 404, got %d", w.Code)
		}
	}
	if _, ok := s.verify(buildAuth("u", "p")); !ok {
		t.Fatal("valid credentials must keep working after bad attempts")
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
