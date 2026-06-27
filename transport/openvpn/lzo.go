package openvpn

import (
	"bytes"
	"errors"

	"github.com/rasky/go-lzo"
)

const (
	lzoCompressNone = 0xFA
	lzoCompressLZO  = 0x66
)

var ErrLZODecompress = errors.New("lzo decompression failed")

func lzo1xDecompressSafe(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, ErrLZODecompress
	}

	switch src[0] {
	case lzoCompressNone:
		if len(src) > 1 {
			return src[1:], nil
		}
		return nil, nil
	case lzoCompressLZO:
		if len(src) > 1 {
			r := bytes.NewReader(src[1:])
			out, err := lzo.Decompress1X(r, len(src)-1, 0)
			if err != nil {
				return nil, ErrLZODecompress
			}
			return out, nil
		}
		return nil, nil
	default:
		return nil, ErrLZODecompress
	}
}

func lzo1xCompressSafe(src []byte) ([]byte, error) {
	lzoPacket := make([]byte, 1+len(src))
	lzoPacket[0] = lzoCompressNone
	copy(lzoPacket[1:], src)
	return lzoPacket, nil
}
