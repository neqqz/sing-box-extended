package fallback

import (
	"context"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type ExchangeStrategy = func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)

func parallelStrategy(servers []adapter.DNSTransport, logger logger.ContextLogger, timeout time.Duration) ExchangeStrategy {
	return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		type result struct {
			response *mDNS.Msg
			err      error
		}
		results := make(chan result)
		for _, server := range servers {
			go func() {
				response, err := checkExchangeResponse(server.Exchange(ctx, message))
				if err != nil {
					logger.InfoContext(ctx, E.Cause(err, "resolve failed for server ", server.Tag()))
				}
				select {
				case results <- result{response, err}:
				case <-ctx.Done():
				}
			}()
		}
		var lastErr error
		for range servers {
			select {
			case result := <-results:
				if result.err != nil {
					lastErr = result.err
					continue
				}
				return result.response, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nil, lastErr
	}
}

func sequentialStrategy(servers []adapter.DNSTransport, logger logger.ContextLogger, timeout time.Duration) ExchangeStrategy {
	return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var lastErr error
		for index, server := range servers {
			exchangeCtx, exchangeCancel := context.WithTimeout(ctx, perAttemptTimeout(ctx, len(servers)-index))
			response, err := checkExchangeResponse(server.Exchange(exchangeCtx, message))
			exchangeCancel()
			if err != nil {
				logger.InfoContext(ctx, E.Cause(err, "resolve failed for server ", server.Tag()))
				lastErr = err
				continue
			}
			return response, nil
		}
		return nil, lastErr
	}
}

func checkExchangeResponse(response *mDNS.Msg, err error) (*mDNS.Msg, error) {
	if err != nil {
		return nil, err
	}
	if response.Rcode != mDNS.RcodeSuccess && response.Rcode != mDNS.RcodeNameError {
		return nil, E.New("bad response rcode: ", mDNS.RcodeToString[response.Rcode])
	}
	return response, nil
}

func perAttemptTimeout(ctx context.Context, remaining int) time.Duration {
	deadline, _ := ctx.Deadline()
	return time.Until(deadline) / time.Duration(remaining)
}

func CreateStrategy(strategy string, servers []adapter.DNSTransport, logger logger.ContextLogger, timeout time.Duration) (ExchangeStrategy, error) {
	if timeout <= 0 {
		timeout = C.DNSTimeout
	}
	switch strategy {
	case "parallel":
		return parallelStrategy(servers, logger, timeout), nil
	case "", "sequential":
		return sequentialStrategy(servers, logger, timeout), nil
	default:
		return nil, E.New("strategy not found: ", strategy)
	}
}
