package trusttunnel

import (
	"bytes"
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func initConn(c *httpConn, body io.ReadCloser, w io.Writer) {
	c.writer, c.created = w, make(chan struct{})
	c.setup(body, nil)
}

func TestUDPFrameRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	client := &clientPacketConn{paddingMin: 5, paddingMax: 9}
	initConn(&client.httpConn, io.NopCloser(&bytes.Buffer{}), &wire)
	payload := []byte("hello udp")
	dst := M.ParseSocksaddrHostPort("1.2.3.4", 53)
	if err := client.writePacketToServer(buf.As(append([]byte(nil), payload...)).ToOwned(), dst); err != nil {
		t.Fatal(err)
	}
	server := &serverPacketConn{}
	initConn(&server.httpConn, io.NopCloser(&wire), io.Discard)
	out := buf.NewPacket()
	defer out.Release()
	got, err := server.readPacketFromClient(out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr.String() != "1.2.3.4" || got.Port != 53 || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("frame mismatch: %v %q", got, out.Bytes())
	}
}

func TestUDPFrameLengthShorterThanHeaderIsError(t *testing.T) {
	frame := make([]byte, 4+2+16+2+16+2+1)
	frame[3] = 1
	server := &serverPacketConn{}
	initConn(&server.httpConn, io.NopCloser(bytes.NewReader(frame)), io.Discard)
	out := buf.NewPacket()
	defer out.Release()
	if _, err := server.readPacketFromClient(out); err == nil {
		t.Fatal("short length must be rejected")
	}
}

func TestValidatePadding(t *testing.T) {
	for _, c := range []struct {
		min, max, limit int
		ok              bool
	}{
		{0, 0, MaxDataPadding, true}, {10, 255, MaxDataPadding, true}, {0, 256, MaxDataPadding, false},
		{5, 4, MaxUDPPadding, false}, {-1, 3, MaxUDPPadding, false}, {0, 65536, MaxUDPPadding, false},
	} {
		if err := ValidatePadding("x", c.min, c.max, c.limit); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v", c, err)
		}
	}
}
