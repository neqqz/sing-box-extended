package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type dummyConn struct {
	net.Conn
	written bytes.Buffer
}

func (d *dummyConn) Write(b []byte) (int, error) {
	return d.written.Write(b)
}

func TestJitterConn(t *testing.T) {
	raw := &dummyConn{}
	conn := NewJitterConn(raw, 5, 10, 2)

	start := time.Now()
	// First 2 writes should have jitter
	_, _ = conn.Write([]byte("one"))
	_, _ = conn.Write([]byte("two"))
	elapsed := time.Since(start)
	if elapsed < 10*time.Millisecond {
		t.Fatalf("expected jitter on first 2 packets, elapsed %v", elapsed)
	}

	// 3rd and subsequent writes should be instant without jitter
	start = time.Now()
	for i := 0; i < 100; i++ {
		_, _ = conn.Write([]byte("fast"))
	}
	elapsed = time.Since(start)
	if elapsed > 10*time.Millisecond {
		t.Fatalf("subsequent writes took too long (%v), jitter was not disabled", elapsed)
	}
}
