package tls

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/common/badtls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServerOptions struct {
	Context        context.Context
	Logger         log.ContextLogger
	Options        option.InboundTLSOptions
	KTLSCompatible bool
}

func NewServer(ctx context.Context, logger log.ContextLogger, options option.InboundTLSOptions) (ServerConfig, error) {
	return NewServerWithOptions(ServerOptions{
		Context: ctx,
		Logger:  logger,
		Options: options,
	})
}

func NewServerWithOptions(options ServerOptions) (ServerConfig, error) {
	if !options.Options.Enabled {
		return nil, nil
	}
	if !options.KTLSCompatible {
		if options.Options.KernelTx {
			options.Logger.Warn("enabling kTLS TX in current scenarios will definitely reduce performance, please checkout https://sing-box.sagernet.org/configuration/shared/tls/#kernel_tx")
		}
	}
	if options.Options.KernelRx {
		options.Logger.Warn("enabling kTLS RX will definitely reduce performance, please checkout https://sing-box.sagernet.org/configuration/shared/tls/#kernel_rx")
	}
	if options.Options.Reality != nil && options.Options.Reality.Enabled {
		return NewRealityServer(options.Context, options.Logger, options.Options)
	}
	return NewSTDServer(options.Context, options.Logger, options.Options)
}

func ServerHandshake(ctx context.Context, conn net.Conn, config ServerConfig) (Conn, error) {
	// Only impose our own C.TCPTimeout deadline if the caller didn't already
	// set one. context.WithTimeout on an already-deadlined parent takes the
	// EARLIER of the two deadlines, so blindly wrapping here silently
	// shortens any longer deadline a caller deliberately set (e.g.
	// trusttunnel's serveConn, which budgets 20s specifically to outlast the
	// client's own 15s C.TCPTimeout) down to 15s — turning an intended
	// margin into a coin-flip race against the client's identical timeout.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, C.TCPTimeout)
		defer cancel()
	}
	tlsConn, err := aTLS.ServerHandshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	readWaitConn, err := badtls.NewReadWaitConn(tlsConn)
	if err == nil {
		return readWaitConn, nil
	} else if err != os.ErrInvalid {
		return nil, err
	}
	return tlsConn, nil
}
