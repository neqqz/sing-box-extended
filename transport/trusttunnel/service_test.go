package trusttunnel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type dummyCloser struct {
	closed bool
	mu     sync.Mutex
}

func (d *dummyCloser) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func TestServiceClose(t *testing.T) {
	s := NewService(ServiceOptions{
		Ctx: context.Background(),
	})
	c1 := &dummyCloser{}
	c2 := &dummyCloser{}

	s.trackConn("user1", c1)
	s.trackConn("user2", c2)

	if err := s.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c1.mu.Lock()
	c1Closed := c1.closed
	c1.mu.Unlock()

	c2.mu.Lock()
	c2Closed := c2.closed
	c2.mu.Unlock()

	if !c1Closed || !c2Closed {
		t.Fatalf("expected all connections to be closed, got c1=%v c2=%v", c1Closed, c2Closed)
	}

	s.mu.Lock()
	remaining := len(s.conns)
	s.mu.Unlock()

	if remaining != 0 {
		t.Fatalf("expected conns map to be empty, got len %d", remaining)
	}
}

func TestServiceFallback(t *testing.T) {
	fallbackBody := "<html>Hello Fallback Site!</html>"
	fallbackHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fallbackBody))
	})

	s := NewService(ServiceOptions{
		Ctx:             context.Background(),
		FallbackHandler: fallbackHandler,
	})

	// 1. Unauthenticated GET request to fallback
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 from fallback, got %d", resp.StatusCode)
	}
	if string(body) != fallbackBody {
		t.Fatalf("expected body %q, got %q", fallbackBody, string(body))
	}

	// 2. Unauthenticated CONNECT request to fallback
	reqConnect := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	recConnect := httptest.NewRecorder()
	s.ServeHTTP(recConnect, reqConnect)
	respConnect := recConnect.Result()
	bodyConnect, _ := io.ReadAll(respConnect.Body)
	if respConnect.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 from fallback for failed auth, got %d", respConnect.StatusCode)
	}
	if string(bodyConnect) != fallbackBody {
		t.Fatalf("expected body %q, got %q", fallbackBody, string(bodyConnect))
	}

	// 3. Service without fallback handler should return standard 404
	sNoFallback := NewService(ServiceOptions{
		Ctx: context.Background(),
	})
	req404 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rec404 := httptest.NewRecorder()
	sNoFallback.ServeHTTP(rec404, req404)
	resp404 := rec404.Result()
	body404, _ := io.ReadAll(resp404.Body)
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp404.StatusCode)
	}
	if !strings.Contains(string(body404), "404 page not found") {
		t.Fatalf("expected standard 404 body, got %q", string(body404))
	}
}
