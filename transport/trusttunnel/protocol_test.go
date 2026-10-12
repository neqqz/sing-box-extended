package trusttunnel

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestHTTPConnDeadlineUnsupported(t *testing.T) {
	var c httpConn
	if err := c.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("SetDeadline must return os.ErrInvalid so sing-box wraps the conn")
	}
	if !c.NeedAdditionalReadDeadline() {
		t.Fatal("NeedAdditionalReadDeadline must be true")
	}
}

func TestHTTPConnCloseUnblocksStuckWrite(t *testing.T) {
	pr, pw := io.Pipe()
	c := &httpConn{writer: pw, created: make(chan struct{})}
	c.cancelFn = func() { _ = pr.CloseWithError(io.ErrClosedPipe) }
	go func() { _ = c.writeChunks([]byte("x")) }() // blocks: nobody reads pr
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hangs behind a blocked Write")
	}
}
