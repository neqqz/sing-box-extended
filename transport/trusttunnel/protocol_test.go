package trusttunnel

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTokenAuthRoundTrip(t *testing.T) {
	username := "testuser"
	password := "secretpassword123"
	target := "example.com:443"

	token := buildTokenAuth(username, password, target)
	if !strings.HasPrefix(token, AuthBearerPrefix) {
		t.Fatalf("expected token to start with %s, got: %s", AuthBearerPrefix, token)
	}

	user, ts, nonce, sig, ok := parseTokenAuth(token)
	if !ok {
		t.Fatalf("failed to parse generated token")
	}
	if user != username {
		t.Fatalf("expected user %s, got %s", username, user)
	}
	if nonce == [8]byte{} {
		t.Fatalf("expected non-zero nonce")
	}
	if len(sig) != 32 {
		t.Fatalf("expected 32-byte sha256 sig, got %d bytes", len(sig))
	}
	now := time.Now().Unix()
	if ts < now-5 || ts > now+5 {
		t.Fatalf("timestamp %d is outside expected window around %d", ts, now)
	}
}

func TestServiceVerify(t *testing.T) {
	s := NewService(ServiceOptions{})
	s.UpdateUsers(map[string]string{
		"alice": "alicepass",
		"bob":   "bobpass",
	})

	target := "target.example.org:443"
	aliceToken := buildTokenAuth("alice", "alicepass", target)

	// 1. Valid authentication
	user, ok := s.verify(aliceToken, target)
	if !ok || user != "alice" {
		t.Fatalf("expected successful verify for alice, got user=%s ok=%v", user, ok)
	}

	// 2. Replay of same token should be rejected
	_, ok = s.verify(aliceToken, target)
	if ok {
		t.Fatalf("expected replay of aliceToken to be rejected")
	}

	// 3. Wrong password
	wrongPassToken := buildTokenAuth("bob", "wrongpass", target)
	_, ok = s.verify(wrongPassToken, target)
	if ok {
		t.Fatalf("expected wrong password to fail verify")
	}

	// 4. Nonexistent user
	charlieToken := buildTokenAuth("charlie", "somepass", target)
	_, ok = s.verify(charlieToken, target)
	if ok {
		t.Fatalf("expected nonexistent user to fail verify")
	}

	// 5. Wrong target binding
	otherTargetToken := buildTokenAuth("bob", "bobpass", "other.example.org:443")
	_, ok = s.verify(otherTargetToken, target)
	if ok {
		t.Fatalf("expected target mismatch to fail verify")
	}
}

func TestAuthReplayCache(t *testing.T) {
	c := newAuthReplayCache()
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := time.Now().Unix()

	if !c.checkAndAdd(nonce, now, 60) {
		t.Fatalf("first checkAndAdd should succeed")
	}

	if c.checkAndAdd(nonce, now, 60) {
		t.Fatalf("duplicate checkAndAdd should fail")
	}

	// After expiration
	if !c.checkAndAdd(nonce, now+61, 60) {
		t.Fatalf("checkAndAdd after TTL expiration should succeed")
	}
}

func TestIPPacking(t *testing.T) {
	testAddrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("192.168.1.254"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("2001:db8::8a2e:370:7334"),
	}

	for _, addr := range testAddrs {
		packed := buildPaddingIP(addr)
		parsed := parse16BytesIP(packed)
		if parsed != addr {
			t.Fatalf("IP round-trip mismatch for %s: got %s (bytes: %v)", addr, parsed, packed)
		}
	}

	// Test legacy IPv4-compatible (::1.2.3.4 with zeros)
	var legacyIPv4 [16]byte
	copy(legacyIPv4[12:16], []byte{10, 0, 0, 1})
	parsedLegacy := parse16BytesIP(legacyIPv4)
	expectedLegacy := netip.MustParseAddr("10.0.0.1")
	if parsedLegacy != expectedLegacy {
		t.Fatalf("expected legacy IPv4 10.0.0.1, got %s", parsedLegacy)
	}
}

func TestUDPPadding(t *testing.T) {
	if err := ValidatePadding("test", 0, 100, MaxUDPPadding); err != nil {
		t.Fatalf("valid padding rejected: %v", err)
	}
	if err := ValidatePadding("test", 100, 50, MaxUDPPadding); err == nil {
		t.Fatalf("expected error for min > max")
	}
	if err := ValidatePadding("test", -1, 50, MaxUDPPadding); err == nil {
		t.Fatalf("expected error for min < 0")
	}
	if err := ValidatePadding("test", 0, MaxUDPPadding+1, MaxUDPPadding); err == nil {
		t.Fatalf("expected error for max > limit")
	}

	for i := 0; i < 100; i++ {
		l := randomUDPPaddingLength(10, 50)
		if l < 10 || l > 50 {
			t.Fatalf("padding length %d outside [10, 50]", l)
		}
		p := randomUDPPadding(l)
		if len(p) != l {
			t.Fatalf("expected padding slice of len %d, got %d", l, len(p))
		}
	}

	if p := randomUDPPadding(0); p != nil {
		t.Fatalf("expected nil for 0 padding")
	}
}
