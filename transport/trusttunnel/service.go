package trusttunnel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

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
	TimeFunc        func() time.Time
}

type Service struct {
	ctx             context.Context
	logger          logger.ContextLogger
	users           map[string]string
	handler         Handler
	conns           map[string]map[io.Closer]struct{}
	replayCache     *authReplayCache
	fallbackHandler http.Handler
	udpPaddingMin   int
	udpPaddingMax   int
	timeFunc        func() time.Time
	closed          bool

	mu sync.RWMutex
}

func NewService(options ServiceOptions) *Service {
	s := &Service{
		ctx:             options.Ctx,
		logger:          options.Logger,
		handler:         options.Handler,
		conns:           make(map[string]map[io.Closer]struct{}),
		replayCache:     newAuthReplayCache(),
		fallbackHandler: options.FallbackHandler,
		udpPaddingMin:   options.UDPPaddingMin,
		udpPaddingMax:   options.UDPPaddingMax,
		timeFunc:        options.TimeFunc,
	}
	return s
}

func (s *Service) now() time.Time {
	if s.timeFunc != nil {
		return s.timeFunc()
	}
	return time.Now()
}

func (s *Service) UpdateUsers(users map[string]string) {
	s.mu.Lock()
	oldUsers := s.users
	s.users = users
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
	authorization := request.Header.Get("Proxy-Authorization")
	if authorization == "" {
		authorization = request.Header.Get("Authorization")
	}
	username, loaded := s.verify(authorization, request.Host)
	if !loaded {
		if s.fallbackHandler != nil {
			s.fallbackHandler.ServeHTTP(writer, request)
			return
		}
		// 407 прямым текстом палит, что порт держит прокси/CONNECT-сервер —
		// любой сканер или DPI, стукнувшийся без валидных кредов, сразу видит
		// сигнатуру. Стандартный 404 неотличим от обычного веб-сервера.
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
		if h == UDPMagicAddress || h == HealthCheckMagicAddress {
			targetHost = h
		}
	}
	switch targetHost {
	case UDPMagicAddress:
		// UDPMagicAddress требует авторизации - уже проверена выше
		writer.WriteHeader(http.StatusOK)
		flusher, isFlusher := writer.(http.Flusher)
		if isFlusher {
			flusher.Flush()
		}
		if streamer, ok := writer.(http3.HTTPStreamer); ok {
			str := streamer.HTTPStream()
			reqCtx, cancel := context.WithCancel(request.Context())
			conn := &quicPacketConn{
				stream:     str,
				ctx:        reqCtx,
				cancel:     cancel,
				remoteAddr: parseRemoteAddr(request.RemoteAddr),
				localAddr:  parseLocalAddr(request),
				paddingMin: s.udpPaddingMin,
				paddingMax: s.udpPaddingMax,
			}
			if !s.trackConn(username, conn) {
				_ = conn.Close()
				return
			}
			defer s.untrackConn(username, conn)
			defer conn.Close()
			firstPacket := buf.NewPacket()
			destination, err := conn.ReadPacket(firstPacket)
			if err != nil {
				firstPacket.Release()
				if isBenignFirstPacketClose(err) {
					s.logger.DebugContext(ctx, E.Cause(err, "read first packet from ", request.RemoteAddr))
				} else {
					s.logger.ErrorContext(ctx, E.Cause(err, "read first packet from ", request.RemoteAddr))
				}
				return
			}
			destination = destination.Unwrap()
			cachedConn := bufio.NewCachedPacketConn(conn, firstPacket, destination)
			defer cachedConn.Close()
			if err = s.handler.NewPacketConnection(ctx, cachedConn, M.Metadata{
				Protocol:    "trusttunnel",
				Source:      M.ParseSocksaddr(request.RemoteAddr),
				Destination: destination,
			}); err != nil {
				return
			}
			<-reqCtx.Done()
			return
		}

		done := make(chan struct{})
		conn := &packetConn{
			httpConn: httpConn{
				writer:     writer,
				flusher:    flusher,
				created:    make(chan struct{}),
				done:       done,
				remoteAddr: parseRemoteAddr(request.RemoteAddr),
				localAddr:  parseLocalAddr(request),
			},
			paddingMin: s.udpPaddingMin,
			paddingMax: s.udpPaddingMax,
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
			// RST_STREAM(CANCEL) от клиента на потоке, который ещё не передал
			// ни одного пакета (мы здесь читаем самый первый) — штатная отмена
			// на стороне клиента (см. тот же диагноз в client.go у dialMu), а
			// не признак обрыва туннеля. На ERROR это забивало лог ложным
			// сигналом "туннель падает" при полностью рабочем сервере: клиент
			// просто передумал открывать UDP-поток раньше, чем сервер успел
			// прочитать из него хоть байт. Другие ошибки (сброс TCP, битые
			// данные, реальный таймаут) остаются ERROR без изменений.
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

// dummyPassword сравнивается вместо настоящего пароля, когда пользователь
// не найден: время ответа не должно зависеть от того, существует ли имя.
const dummyPassword = "trusttunnel-dummy-password"

func (s *Service) verify(authorization, target string) (username string, loaded bool) {
	user, ts, nonce, gotSig, ok := parseTokenAuth(authorization)
	if !ok {
		return "", false
	}
	now := s.now().Unix()
	if ts < now-AuthMaxSkewSec || ts > now+AuthMaxSkewSec {
		return "", false
	}
	s.mu.RLock()
	recordedPassword, known := s.users[user]
	s.mu.RUnlock()
	if !known {
		recordedPassword = dummyPassword
	}
	userBytes := []byte(user)
	userLen := len(userBytes)
	var prefix [tokenHeaderLen]byte
	prefix[0] = TokenVersion
	binary.BigEndian.PutUint64(prefix[1:9], uint64(ts))
	copy(prefix[9:17], nonce[:])
	binary.BigEndian.PutUint16(prefix[17:19], uint16(userLen))

	mac := hmac.New(sha256.New, []byte(recordedPassword))
	mac.Write(prefix[:])
	mac.Write(userBytes)
	mac.Write([]byte(target))
	var wantSigBuf [sha256.Size]byte
	wantSig := mac.Sum(wantSigBuf[:0])

	match := subtle.ConstantTimeCompare(gotSig, wantSig) == 1
	if !known || !match {
		return "", false
	}
	if !s.replayCache.checkAndAdd(nonce, now, AuthMaxSkewSec*2) {
		return "", false
	}
	return user, true
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
