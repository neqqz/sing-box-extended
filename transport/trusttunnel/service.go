package trusttunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

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
	Ctx           context.Context
	Logger        logger.ContextLogger
	Handler       Handler
	UDPPaddingMin int
	UDPPaddingMax int
}

type Service struct {
	ctx           context.Context
	logger        logger.ContextLogger
	users         map[string]string
	handler       Handler
	conns         map[string][]io.Closer
	udpPaddingMin int
	udpPaddingMax int

	mu sync.RWMutex
}

func NewService(options ServiceOptions) *Service {
	return &Service{
		ctx:           options.Ctx,
		logger:        options.Logger,
		handler:       options.Handler,
		conns:         make(map[string][]io.Closer),
		udpPaddingMin: options.UDPPaddingMin,
		udpPaddingMax: options.UDPPaddingMax,
	}
}

func (s *Service) UpdateUsers(users map[string]string) {
	s.mu.Lock()
	s.users = users
	var closedConns []io.Closer
	for user, conns := range s.conns {
		if _, exists := users[user]; !exists {
			closedConns = append(closedConns, conns...)
			delete(s.conns, user)
		}
	}
	s.mu.Unlock()
	for _, conn := range closedConns {
		conn.Close()
	}
}

func (s *Service) trackConn(username string, conn io.Closer) {
	s.mu.Lock()
	s.conns[username] = append(s.conns[username], conn)
	s.mu.Unlock()
}

func (s *Service) untrackConn(username string, conn io.Closer) {
	s.mu.Lock()
	conns := s.conns[username]
	for i, c := range conns {
		if c == conn {
			s.conns[username] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

func (s *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	authorization := request.Header.Get("Proxy-Authorization")
	username, loaded := s.verify(authorization)
	if !loaded {
		// 407 прямым текстом палит, что порт держит прокси/CONNECT-сервер —
		// любой сканер или DPI, стукнувшийся без валидных креды, сразу видит
		// сигнатуру. 404 неотличим от обычного веб-сервера, у которого просто
		// нет такого пути — камуфляж уровня SNI/random-prefix, только для
		// самого HTTP-ответа.
		writer.WriteHeader(http.StatusNotFound)
		s.badRequest(request.Context(), request, E.New("authorization failed"))
		return
	}
	if request.Method != http.MethodConnect {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		s.badRequest(request.Context(), request, E.New("unexpected HTTP method ", request.Method))
		return
	}
	ctx := request.Context()
	ctx = auth.ContextWithUser(ctx, username)
	switch request.Host {
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
			},
			paddingMin: s.udpPaddingMin,
			paddingMax: s.udpPaddingMax,
		}
		conn.setup(request.Body, nil)
		s.trackConn(username, conn)
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
		_ = s.handler.NewPacketConnection(ctx, cachedConn, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: destination,
		})
		<-done
		s.untrackConn(username, conn)
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
			httpConn{
				writer:     writer,
				flusher:    flusher,
				created:    make(chan struct{}),
				done:       done,
				remoteAddr: parseRemoteAddr(request.RemoteAddr),
			},
		}
		conn.setup(request.Body, nil)
		// Устанавливаем таймаут простоя для TCP-стрима при создании
		_ = conn.SetDeadline(time.Now().Add(TCPStreamIdleTimeout))
		wrapper := &h2ConnWrapper{Conn: conn}
		s.trackConn(username, wrapper)
		_ = s.handler.NewConnection(ctx, wrapper, M.Metadata{
			Protocol:    "trusttunnel",
			Source:      M.ParseSocksaddr(request.RemoteAddr),
			Destination: M.ParseSocksaddr(request.Host).Unwrap(),
		})
		<-done
		s.untrackConn(username, wrapper)
		wrapper.CloseWrapper()
	}
}

func (s *Service) verify(authorization string) (username string, loaded bool) {
	username, password, loaded := parseBasicAuth(authorization)
	if !loaded {
		return "", false
	}
	s.mu.RLock()
	recordedPassword, loaded := s.users[username]
	s.mu.RUnlock()
	if !loaded {
		return "", false
	}
	if password != recordedPassword {
		return "", false
	}
	return username, true
}

func (s *Service) badRequest(ctx context.Context, request *http.Request, err error) {
	s.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
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
	return errors.Is(err, io.EOF)
}

func parseRemoteAddr(addr string) net.Addr {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil
	}
	return tcpAddr
}

type h2ConnWrapper struct {
	net.Conn
	access sync.Mutex
	closed bool
}

func (w *h2ConnWrapper) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	return w.Conn.Write(p)
}

func (w *h2ConnWrapper) CloseWrapper() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
}
