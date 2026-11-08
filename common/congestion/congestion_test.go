package congestion

import (
	"testing"
)

func TestNewCongestionControl(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"", false},
		{"bbr", false},
		{"bbr2", false},
		{"bbr3", false},
		{"bbr_standard", false},
		{"bbr_aggressive", false},
		{"bbr_conservative", false},
		{"cubic", false},
		{"reno", false},
		{"BBR", false},
		{"BBR3", false},
		{"unknown_algo", true},
	}

	for _, tc := range cases {
		_, err := NewCongestionControl(tc.name, 32, nil)
		if tc.wantErr && err == nil {
			t.Errorf("expected error for %q, got nil", tc.name)
		} else if !tc.wantErr && err != nil {
			t.Errorf("unexpected error for %q: %v", tc.name, err)
		}
	}
}
