package trusttunnel

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type countCloser struct{ n atomic.Int32 }

func (c *countCloser) Close() error { c.n.Add(1); return nil }

func TestCloseOnCancelClosesWhenContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &countCloser{}
	done := make(chan struct{})
	closeOnCancel(ctx, c, done)
	cancel()
	deadline := time.After(2 * time.Second)
	for c.n.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("not closed after context cancel")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestCloseOnCancelDoesNothingWhenDoneFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &countCloser{}
	done := make(chan struct{})
	closeOnCancel(ctx, c, done)
	close(done)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
	if c.n.Load() != 0 {
		t.Fatal("closed after done")
	}
}
