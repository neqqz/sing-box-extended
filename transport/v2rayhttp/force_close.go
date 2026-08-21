package v2rayhttp

import (
	"net/http"
	"reflect"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

// ResetTransport closes idle connections and returns a fresh RoundTripper
// so that subsequent requests do not reuse any previous connections.
//
// For *http2.Transport a new instance is created with the same settings.
// This works with both the legacy implementation and the Go 1.27+ wrapped
// implementation (no //go:linkname or unsafe required).
func ResetTransport(rawTransport http.RoundTripper) http.RoundTripper {
	switch t := rawTransport.(type) {
	case *http.Transport:
		t.CloseIdleConnections()
		return t.Clone()

	case *http2.Transport:
		t.CloseIdleConnections()

		// Return a brand-new transport with identical configuration.
		// The old connection pool is discarded completely.
		return &http2.Transport{
			DialTLS:                    t.DialTLS,
			DialTLSContext:             t.DialTLSContext,
			TLSClientConfig:            t.TLSClientConfig,
			ConnPool:                   t.ConnPool,
			DisableCompression:         t.DisableCompression,
			AllowHTTP:                  t.AllowHTTP,
			MaxHeaderListSize:          t.MaxHeaderListSize,
			MaxReadFrameSize:           t.MaxReadFrameSize,
			MaxDecoderHeaderTableSize:  t.MaxDecoderHeaderTableSize,
			MaxEncoderHeaderTableSize:  t.MaxEncoderHeaderTableSize,
			StrictMaxConcurrentStreams: t.StrictMaxConcurrentStreams,
			IdleConnTimeout:            t.IdleConnTimeout,
			ReadIdleTimeout:            t.ReadIdleTimeout,
			PingTimeout:                t.PingTimeout,
			WriteByteTimeout:           t.WriteByteTimeout,
			CountError:                 t.CountError,
			DataPaddingMin:             t.DataPaddingMin,
			DataPaddingMax:             t.DataPaddingMax,
		}

	default:
		panic(E.New("unknown transport type: ", reflect.TypeOf(rawTransport)))
	}
}
