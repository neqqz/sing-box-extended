//go:build with_utls

package trusttunnel

import (
	"context"
	"strings"
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

func TestClientUserAgent(t *testing.T) {
	// 1. Default user-agent should match ChromeUA
	cDefault, err := NewClient(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer cDefault.Close()

	reqDefault := cDefault.newConnectRequest("example.com:443")
	ua := reqDefault.Header.Get("User-Agent")
	if !strings.Contains(ua, "Chrome") {
		t.Fatalf("expected default User-Agent to contain Chrome, got %q", ua)
	}

	// 2. Custom user-agent
	customUA := "Mozilla/5.0 (CustomBrowser/1.0)"
	cCustom, err := NewClient(context.Background(), ClientOptions{UserAgent: customUA})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer cCustom.Close()

	reqCustom := cCustom.newConnectRequest("example.com:443")
	if got := reqCustom.Header.Get("User-Agent"); got != customUA {
		t.Fatalf("expected User-Agent %q, got %q", customUA, got)
	}

	// 3. User-Agent "none" should suppress User-Agent header
	cNone, err := NewClient(context.Background(), ClientOptions{UserAgent: "none"})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	defer cNone.Close()

	reqNone := cNone.newConnectRequest("example.com:443")
	if vals, ok := reqNone.Header["User-Agent"]; !ok || len(vals) != 1 || vals[0] != "" {
		t.Fatalf("expected empty User-Agent slice to suppress Go default, got %#v", vals)
	}
}
