//go:build !linux

package trusttunnel

import (
	"net"
	"time"
)

// DefaultTCPUserTimeout is unused on non-Linux platforms; kept so callers
// don't need a build-tag branch just to reference the constant.
const DefaultTCPUserTimeout = 15 * time.Second

// SetTCPUserTimeout: TCP_USER_TIMEOUT is Linux-specific
// (setsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT, ...)). Windows has no directly
// equivalent portable knob (closest is per-connection SIO_KEEPALIVE_VALS,
// which is keepalive-shaped, not "give up on unacked in-flight data" like
// TCP_USER_TIMEOUT) and macOS/BSD's TCP_RXT_CONNDROPTIME is close but not
// exposed by golang.org/x/sys/unix in a portable way here — silently do
// nothing and stay on the system default, same as SetTCPCongestionControl's
// non-Linux stub.
func SetTCPUserTimeout(net.Conn, time.Duration) {}
