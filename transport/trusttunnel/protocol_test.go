package trusttunnel

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TesthttpConnDeadlineUnsupported(t *testing.T) {
	var c httpConn
	if err := c.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("SetDeadline must return os.ErrInvalid so sing-box wraps the conn")
	}
	if !c.NeedAdditionalReadDeadline() {
		t.Fatal("NeedAdditionalReadDeadline must be true")
	}
}
