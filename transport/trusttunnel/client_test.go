//go:build with_utls

package trusttunnel

import (
	"context"
	"testing"
)

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
