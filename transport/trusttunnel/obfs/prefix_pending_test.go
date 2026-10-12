package obfs

import (
	"net"
	"net/netip"
	"testing"
)

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

func TestAcquirePendingPerIPLimit(t *testing.T) {
	l := &PrefixChecker{matchSem: make(chan struct{}, maxPendingChecks), pendingByIP: map[netip.Addr]int{}}
	scanner := addrConn{addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1}}
	other := addrConn{addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.2"), Port: 1}}
	var releases []func()
	for i := 0; i < maxPendingChecksPerIP; i++ {
		_, rel, ok := l.acquirePending(scanner)
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		releases = append(releases, rel)
	}
	if _, _, ok := l.acquirePending(scanner); ok {
		t.Fatal("per-IP limit not enforced")
	}
	_, rel, ok := l.acquirePending(other)
	if !ok {
		t.Fatal("other IP starved")
	}
	rel()
	releases[0]()
	if _, rel, ok := l.acquirePending(scanner); !ok {
		t.Fatal("slot not released")
	} else {
		rel()
	}
	for _, r := range releases[1:] {
		r()
	}
	if len(l.pendingByIP) != 0 || len(l.matchSem) != 0 {
		t.Fatal("leak")
	}
}
