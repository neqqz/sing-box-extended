package trusttunnel

import (
	"context"
	"encoding/base64"

	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
}

type ServiceOptions struct {
	Ctx             context.Context
	Logger          logger.ContextLogger
	Handler         Handler
	FallbackHandler http.Handler
	UDPPaddingMin   int
	UDPPaddingMax   int
}

type Service struct {
	ctx             context.Context
	logger          logger.ContextLogger
	users           map[string]string
	authUsers       map[string]string
	handler         Handler
	conns           map[string]map[io.Closer]struct{}
	fallbackHandler http.Handler
	udpPaddingMin   int
	udpPaddingMax   int
	closed          bool

	mu sync.RWMutex
}

func NewService(options ServiceOptions) *Service {
	s := &Service{
		ctx:             options.Ctx,
		logger:          options.Logger,
		handler:         options.Handler,
		authUsers:       make(map[string]string),
		conns:           make(map[string]map[io.Closer]struct{}),
		fallbackHandler: options.FallbackHandler,
		udpPaddingMin:   options.UDPPaddingMin,
		udpPaddingMax:   options.UDPPaddingMax,
	}
	return s
}

func (s *Service) UpdateUsers(users map[string]string) {
	authUsers := make(map[string]string, len(users))
	for username, password := range users {
		authUsers[base64.StdEncoding.EncodeToString([]byte(username+":"+password))] = username
	}
	s.mu.Lock()
	oldUsers := s.users
	s.users = users
	s.authUsers = authUsers
	var closedConns []io.Closer
	for user, conns := range s.conns {
		if pass, exists := users[user]; !exists || pass != oldUsers[user] {
			for conn := range conns {
				closedConns = append(closedConns, conn)
			}
			delete(s.conns, user)
		}
	}
	s.mu.Unlock()
	for _, conn := range closedConns {
		_ = conn.Close()
	}
}

func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	var closedConns []io.Closer
	for _, conns := range s.conns {
		for conn := range conns {
			closedConns = append(closedConns, conn)
		}
	}
	clear(s.conns)
	s.mu.Unlock()
	for _, conn := range closedConns {
		_ = conn.Close()
	}
	return nil
}

func (s *Service) trackConn(username string, conn io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.conns[username] == nil {
		s.conns[username] = make(map[io.Closer]struct{})
	}
	s.conns[username][conn] = struct{}{}
	return true
}

func (s *Service) untrackConn(username string, conn io.Closer) {
	s.mu.Lock()
	delete(s.conns[username], conn)
	if len(s.conns[username]) == 0 {
		delete(s.conns, username)
	}
	s.mu.Unlock()
}

func (s *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	username, loaded := s.verify(request.Header.Get("Proxy-Authorization"))
	if !loaded {
		if s.fallbackHandler != nil {
			s.fallbackHandler.ServeHTTP(writer, request)
			return
		}
		// 404 неотличим от обычного веб-сервера и не выдаёт сигнатуру
		// CONNECT-прокси (в отличие от 407 Proxy Authentication Required).
		http.NotFound(writer, request)
		s.badRequest(request.Context(), request, E.New("authorization failed"))
		return
	}

	if request.Method != http.MethodConnect {
		if s.fallbackHandler != nil {
			s.fallbackHandler.ServeHTTP(writer, request)
			return
		}
		http.NotFound(writer, request)
		s.badRequest(request.Context(), request, E.New("unexpected HTTP method ", request.Method))
		return
	}
	ctx := request.Context()
	ctx = auth.ContextWithUser(ctx, username)
	targetHost := request.Host
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		if h == UDPMagicAddress || h == HealthCheckMagicAddress || h == ICMPMagicAddress {
			targetHost = h
		}
	}
	switch targetHost {
	case UDPMagicAddress:
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		done := make(chan struct{})
		conn := &serverPacketConn{
			httpConn: httpConn{
				writer:     writer,
				flusher:    flusher,
				created:    make(chan struct{}),
				done:       done,
				remoteAddr: parseRemoteAddr(request.RemoteAddr),
				localAddr:  parseLocalAddr(request),
			},
		}
		conn.setup(request.Body, nil)
		if !s.trackConn(username, conn) {
			_ = conn.Close()
			return
		}
		closeOnCancel(request.Context(), conn, done)
		firstPacket := buf.NewPacket()
		destination, err := conn.ReadPacket(firstPacket)
		if err != nil {
			firstPacket.Release()
			s.untrackConn(username, conn)
			_ = conn.Close()
			if isBenignFirstPacketClose(err) {
				s.logger.DebugContext(ctx, E.Cause(err, "read first packet from ", request.RemoteAddr))
			} else {
				s.logger.ErrorContext(ctx, E.Cause(err, "read first packet from ", request.RemoteAddr))
			}
			return
		}
		destination = destination.Unwrap()
		cachedConn := bufio.NewCachedPacketConn(conn, firstPacket, destination)
		if err = s.handler.NewPacketConnection(ctx, cachedConn, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: destination,
		}); err != nil {
			_ = cachedConn.Close()
			_ = conn.Close()
			s.untrackConn(username, conn)
			return
		}
		<-done
		s.untrackConn(username, conn)
		_ = cachedConn.Close()
	case HealthCheckMagicAddress:
		writer.WriteHeader(http.StatusOK)
		if flusher, isFlusher := writer.(http.Flusher); isFlusher {
			flusher.Flush()
		}
		_ = request.Body.Close()
	case ICMPMagicAddress:
		writer.WriteHeader(http.StatusNotImplemented)
		_ = request.Body.Close()
	default:
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		done := make(chan struct{})
		conn := &tcpConn{
			httpConn: httpConn{
				writer:     writer,
				flusher:    flusher,
				created:    make(chan struct{}),
				done:       done,
				remoteAddr: parseRemoteAddr(request.RemoteAddr),
				localAddr:  parseLocalAddr(request),
			},
		}
		conn.setup(request.Body, nil)
		if !s.trackConn(username, conn) {
			_ = conn.Close()
			return
		}
		closeOnCancel(request.Context(), conn, done)
		if err := s.handler.NewConnection(ctx, conn, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: M.ParseSocksaddr(request.Host).Unwrap(),
		}); err != nil {
			_ = conn.Close()
			s.untrackConn(username, conn)
			return
		}
		<-done
		s.untrackConn(username, conn)
	}
}

func (s *Service) verify(authorization string) (username string, loaded bool) {
	credentials, parsed := parseAuth(authorization)
	if !parsed {
		return "", false
	}
	s.mu.RLock()
	username, known := s.authUsers[credentials]
	s.mu.RUnlock()
	return username, known
}

// badRequest logs at debug level: every scanner that reaches the HTTP layer
// ends up here, so ERROR would let anyone fill the log.
func (s *Service) badRequest(ctx context.Context, request *http.Request, err error) {
	if s.logger != nil {
		s.logger.DebugContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
	}
}

// isBenignFirstPacketClose сообщает, является ли err штатной, инициированной
// САМИМ клиентом отменой потока, который ещё не передал ни одного пакета —
// а не признаком реальной проблемы на пути. Два варианта, которыми клиент
// это делает:
//   - HTTP/2 RST_STREAM с кодом CANCEL (явная отмена);
//   - обычный io.EOF — клиент закрыл свою сторону (body/контекст) локально,
//     БЕЗ явного RST_STREAM. Возникает, например, когда клиент параллельно
//     пробует несколько адресов-кандидатов (QUIC/UDP happy-eyeballs-стиль,
//     типично для приложений вроде TikTok) и бросает все потоки, кроме
//     выигравшего, — тот, что бросили, никогда не увидит ни байта payload'а.
//     До этой правки такой EOF не отличался от isStreamCancel и логировался
//     на ERROR, хотя семантически это тот же самый "клиент передумал до
//     первого байта", просто без явного RST_STREAM — заваливало лог тысячами
//     ложных ERROR при полностью исправном туннеле.
func isBenignFirstPacketClose(err error) bool {
	var streamErr http2.StreamError
	if errors.As(err, &streamErr) && streamErr.Code == http2.ErrCodeCancel {
		return true
	}
	var quicStreamErr *quic.StreamError
	if errors.As(err, &quicStreamErr) && (quicStreamErr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeRequestCanceled) || quicStreamErr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeNoError)) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)
}

func parseRemoteAddr(addr string) net.Addr {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	return tcpAddr
}

func parseLocalAddr(r *http.Request) net.Addr {
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return la
	}
	return nil
}
