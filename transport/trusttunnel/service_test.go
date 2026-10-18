package trusttunnel

import (
	"context"
	"io"
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

func TestMultiplexClientCompaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadCtx, deadCancel := context.WithCancel(ctx)
	deadCancel()

	c := &MultiplexClient{
		ctx:     ctx,
		clients: []*Client{{ctx: deadCtx}, {ctx: ctx}},
	}

	// Compact dead clients
	n := 0
	for _, client := range c.clients {
		if client.ctx.Err() == nil {
			c.clients[n] = client
			n++
		}
	}
	clear(c.clients[n:])
	c.clients = c.clients[:n]

	if len(c.clients) != 1 {
		t.Fatalf("expected 1 alive client, got %d", len(c.clients))
	}
	if c.clients[0].ctx.Err() != nil {
		t.Fatalf("expected surviving client to be active")
	}
}
