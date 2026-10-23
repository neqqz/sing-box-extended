package trusttunnel

import (
	"context"
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
