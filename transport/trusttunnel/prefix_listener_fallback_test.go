package trusttunnel

import "testing"

func TestResolveFallbackPort(t *testing.T) {
	cases := []struct {
		name     string
		fallback string
		sniPort  int
		want     string
	}{
		{"nothing configured defaults to 443", "", 0, "443"},
		{"static fallback port is used by default (historical behaviour)", "x5.com:8443", 0, "8443"},
		{"explicit port wins over the static fallback port", "127.0.0.1:8444", 443, "443"},
		{"explicit port works without a static fallback", "", 8443, "8443"},
		{"unparsable static fallback falls back to 443", "not-a-hostport", 0, "443"},
	}
	for _, tc := range cases {
		if got := resolveFallbackPort(tc.fallback, tc.sniPort); got != tc.want {
			t.Errorf("%s: resolveFallbackPort(%q, %d) = %q, want %q", tc.name, tc.fallback, tc.sniPort, got, tc.want)
		}
	}
}
