package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// newGateTestRouter builds the minimal Router needed to exercise the
// "wait until started" gate in routeConnection / routePacketConnection.
func newGateTestRouter(ctx context.Context) *Router {
	return &Router{
		ctx:     ctx,
		started: make(chan struct{}),
	}
}

// gateMetadata returns metadata that hits the InboundDetour loop-detection
// branch (LastInbound == InboundDetour), so routeConnection /
// routePacketConnection return immediately once the gate is open, without
// needing any outbound/inbound managers.
func gateMetadata() adapter.InboundContext {
	return adapter.InboundContext{InboundDetour: "self", LastInbound: "self"}
}

// TestRouteConnectionWaitsForStart verifies that a connection arriving before
// the router finishes starting (StartStatePostStart) blocks until the started
// channel is closed, then proceeds, instead of dereferencing a nil
// defaultOutbound.
func TestRouteConnectionWaitsForStart(t *testing.T) {
	r := newGateTestRouter(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- r.routeConnection(context.Background(), nil, gateMetadata(), nil)
	}()

	// The gate must block while the router is not yet started.
	select {
	case <-done:
		t.Fatal("routeConnection returned before router was started")
	case <-time.After(50 * time.Millisecond):
	}

	// Simulate StartStatePostStart completing.
	close(r.started)

	select {
	case err := <-done:
		// We expect to have passed the gate and reached the loop-detection branch,
		// which returns the "routing loop on detour" error.
		if err == nil {
			t.Fatal("expected routing-loop error after gate opened, got nil")
		}
	case <-time.After(time.Second):
		t.Fatal("routeConnection did not proceed after router started")
	}
}

// TestRoutePacketConnectionWaitsForStart is the UDP counterpart.
func TestRoutePacketConnectionWaitsForStart(t *testing.T) {
	r := newGateTestRouter(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- r.routePacketConnection(context.Background(), nil, gateMetadata(), nil)
	}()

	select {
	case <-done:
		t.Fatal("routePacketConnection returned before router was started")
	case <-time.After(50 * time.Millisecond):
	}

	close(r.started)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected routing-loop error after gate opened, got nil")
		}
	case <-time.After(time.Second):
		t.Fatal("routePacketConnection did not proceed after router started")
	}
}

// TestRouteConnectionAbortsOnConnContext verifies that a client disconnecting
// during startup unblocks the gate via the per-connection context, instead of
// hanging until the router starts.
func TestRouteConnectionAbortsOnConnContext(t *testing.T) {
	r := newGateTestRouter(context.Background())

	connCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.routeConnection(connCtx, nil, gateMetadata(), nil)
	}()

	select {
	case <-done:
		t.Fatal("routeConnection returned before context was cancelled")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("routeConnection did not abort on connection context cancellation")
	}
}

// TestRouteConnectionAbortsOnRouterContext verifies that shutting down the box
// (router context cancellation) unblocks an in-flight early connection.
func TestRouteConnectionAbortsOnRouterContext(t *testing.T) {
	routerCtx, cancel := context.WithCancel(context.Background())
	r := newGateTestRouter(routerCtx)

	done := make(chan error, 1)
	go func() {
		done <- r.routeConnection(context.Background(), nil, gateMetadata(), nil)
	}()

	select {
	case <-done:
		t.Fatal("routeConnection returned before router context was cancelled")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("routeConnection did not abort on router context cancellation")
	}
}
