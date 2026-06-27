package obfs

import (
	"bufio"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"time"
)

// HTTPObfsServer is the server side of the shadowsocks http simple-obfs implementation.
type HTTPObfsServer struct {
	net.Conn
	buf           []byte
	bio           *bufio.Reader
	offset        int
	firstRequest  bool
	firstResponse bool
}

func (hos *HTTPObfsServer) Read(b []byte) (int, error) {
	if hos.buf != nil {
		n := copy(b, hos.buf[hos.offset:])
		hos.offset += n
		if hos.offset == len(hos.buf) {
			hos.offset = 0
			hos.buf = nil
		}
		return n, nil
	}
	if hos.firstRequest {
		bio := bufio.NewReader(hos.Conn)
		req, err := http.ReadRequest(bio)
		if err != nil {
			return 0, err
		}
		if req.Method != "GET" || req.Header.Get("Connection") != "Upgrade" {
			return 0, io.EOF
		}
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			return 0, err
		}
		n := copy(b, buf)
		if n < len(buf) {
			hos.buf = buf
			hos.offset = n
		}
		req.Body.Close()
		hos.bio = bio
		hos.firstRequest = false
		return n, nil
	}
	return hos.bio.Read(b)
}

func (hos *HTTPObfsServer) Write(b []byte) (int, error) {
	if hos.firstResponse {
		randBytes := make([]byte, 16)
		cryptorand.Read(randBytes)
		date := time.Now().Format(time.RFC1123)
		resp := fmt.Sprintf(httpResponseTemplate, vMajor, vMinor, date, base64.URLEncoding.EncodeToString(randBytes))
		_, err := hos.Conn.Write([]byte(resp))
		if err != nil {
			return 0, err
		}
		hos.firstResponse = false
	}
	return hos.Conn.Write(b)
}

func (hos *HTTPObfsServer) Upstream() any {
	return hos.Conn
}

// NewHTTPObfsServer returns a server-side HTTPObfs.
func NewHTTPObfsServer(conn net.Conn) net.Conn {
	return &HTTPObfsServer{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
	}
}

const httpResponseTemplate = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Server: nginx/1.%d.%d\r\n" +
	"Date: %s\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: %s\r\n" +
	"\r\n"

var (
	vMajor = rand.IntN(11)
	vMinor = rand.IntN(12)
)
