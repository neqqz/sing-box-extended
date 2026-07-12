package trusttunnel

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/congestion"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"golang.org/x/net/http2"
)

var (
	appName       = "sing-box"
	appVersion    = C.Version
	tcpUserAgent  = runtime.GOOS + " " + appName + "/" + appVersion
	udpUserAgent  = runtime.GOOS + " " + UDPMagicAddress
	icmpUserAgent = runtime.GOOS + " " + ICMPMagicAddress
)

type Dialer interface {
	Dial(ctx context.Context, host string) (net.Conn, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
	Close() error
}

type ClientOptions struct {
	Dialer            N.Dialer
	TLSConfig         tls.Config
	Server            M.Socksaddr
	Username          string
	Password          string
	QUIC              bool
	CongestionControl string
	CWND              int
	Logger            logger.Logger
	HealthCheck       bool
	MaxConnections    int
	MinStreams        int
	MaxStreams        int
	UDPPaddingMin     int
	UDPPaddingMax     int
}

type Client struct {
	ctx              context.Context
	cancel           context.CancelFunc
	server           M.Socksaddr
	serverString     string
	auth             string
	roundTripper     http.RoundTripper
	session          *h2Session 
	quicConnMu       sync.RWMutex
	quicConn         *quic.Conn 
	startOnce        sync.Once
	healthCheck      bool
	healthCheckTimer *time.Timer
	count            atomic.Int64
	udpPaddingMin    int
	udpPaddingMax    int
}

type h2Session struct {
	transport *http2.Transport
	server    M.Socksaddr
	tlsDialer tls.Dialer
	// ctx — контекст владеющего Client'а (не запроса). Нужен ТОЛЬКО чтобы
	// оборвать зависший дозвон нового соединения (см. ниже в
	// GetClientConn), когда Close()/InterfaceUpdated() уже знают, что путь
	// сдох (смена интерфейса на мобильной сети — хендовер вышки,
	// rmnet-интерфейс пересоздан и т.п.), а сам дозвон слушает только
	// req.Context() и без этого ждал бы полный C.TCPTimeout вслепую. На
	// уже установленные стримы это НЕ влияет: у них свой независимый
	// контекст (см. комментарий в roundTrip), этот ctx used только вокруг
	// самого TCP/TLS dial.
	ctx context.Context

	mu         sync.Mutex
	clientConn *http2.ClientConn
	dead       bool
	// dialMu — канал-мьютекс вместо sync.Mutex по той же причине, что и
	// MultiplexClient.mu (см. комментарий там): обычный sync.Mutex.Lock()
	// ничем не ограничен по времени. Пока один стрим реально дозванивается
	// (до C.TCPTimeout), остальные конкурентные стримы того же
	// h2Session вставали в очередь на dialMu и ждали БЕЗ учёта СВОЕГО
	// собственного req.Context() — это ожидание в очереди не считалось ни
	// в C.TCPTimeout, ни в серверный дедлайн, оба тикали только с момента
	// реального захвата мьютекса. В результате к тому моменту, когда
	// стрим наконец получал dialMu, его собственный таймаут зачастую уже
	// истёк, и он тут же валился с "operation was canceled", даже не
	// начав дозвон — именно это давало наблюдаемую лавину обрывов http2
	// (разброс от долей секунды до 18+s с начала стрима при
	// C.TCPTimeout=15s) и по цепочке RST_STREAM(CANCEL) на сервере на
	// едва открытые стримы. Канал даёт то же взаимоисключение, но
	// ожидание прерывается по req.Context() вызывающего стрима: если
	// стрим не дождался своей очереди на дозвон, он не тратит время
	// впустую и не пытается дозвониться с уже просроченным бюджетом.
	dialMu chan struct{}
}

// lockDial ждёт свободный слот на дозвон, но не дольше, чем жив ctx.
func (s *h2Session) lockDial(ctx context.Context) error {
	select {
	case s.dialMu <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *h2Session) unlockDial() {
	<-s.dialMu
}

func (s *h2Session) GetClientConn(req *http.Request, _ string) (*http2.ClientConn, error) {
	s.mu.Lock()
	if s.clientConn != nil && !s.dead {
		state := s.clientConn.State()
		if !state.Closed && !state.Closing {
			cc := s.clientConn
			s.mu.Unlock()
			return cc, nil
		}
	}
	s.mu.Unlock()

	if err := s.lockDial(req.Context()); err != nil {
		return nil, err
	}
	defer s.unlockDial()

	s.mu.Lock()
	if s.clientConn != nil && !s.dead {
		state := s.clientConn.State()
		if !state.Closed && !state.Closing {
			cc := s.clientConn
			s.mu.Unlock()
			return cc, nil
		}
	}
	s.mu.Unlock()

	// Дозвон слушает req.Context() (свой таймаут стрима) И s.ctx (ctx
	// владеющего Client'а). Раньше слушался только первый: если во время
	// зависшего TCP/TLS-дозвона происходил реальный Close()/
	// InterfaceUpdated() (интерфейс сменился, старый путь гарантированно
	// мёртв), дозвон об этом не узнавал и висел до полного C.TCPTimeout —
	// а за это время в очередь на этот же дозвон (dialMu) успевали
	// встать остальные стримы, которые все разом падали с "context
	// canceled/operation was canceled" по истечении СВОЕГО таймаута. Это
	// и есть волнообразные обрывы http2-пути при смене сети на мобильных
	// клиентах. Обрыв по s.ctx сразу освобождает dialMu и даёт следующему
	// стриму немедленно поднять новый дозвон вместо ожидания вслепую.
	dialCtx, dialCancel := context.WithCancel(req.Context())
	if s.ctx != nil {
		stop := context.AfterFunc(s.ctx, dialCancel)
		defer stop()
	}
	conn, err := s.tlsDialer.DialContext(dialCtx, N.NetworkTCP, s.server)
	dialCancel()
	if err != nil {
		return nil, err
	}
	clientConn, err := s.transport.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	s.mu.Lock()
	s.clientConn = clientConn
	s.dead = false
	s.mu.Unlock()

	return clientConn, nil
}

func (s *h2Session) MarkDead(conn *http2.ClientConn) {
	s.mu.Lock()
	if conn == s.clientConn {
		s.dead = true
	}
	s.mu.Unlock()
}

// status возвращает (hardClosed, draining) для текущего clientConn.
// hardClosed — соединение реально мертво (transport.MarkDead его отбраковал,
// либо http2 сообщает state.Closed): активные стримы на нём уже ни на что
// не годны, их контекст можно смело отменять.
// draining — получен GOAWAY, http2.ClientConn в state.Closing: НЕ новых
// стримов, но уже открытые стримы по спецификации HTTP/2 должны доиграть
// до конца. Это не то же самое, что "мертво".
func (s *h2Session) status() (hardClosed, draining bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientConn == nil {
		return false, false
	}
	if s.dead {
		return true, false
	}
	state := s.clientConn.State()
	return state.Closed, state.Closing
}

func (s *h2Session) isClosed() bool {
	hardClosed, draining := s.status()
	return hardClosed || draining
}

func (s *h2Session) isHardClosed() bool {
	hardClosed, _ := s.status()
	return hardClosed
}

func (s *h2Session) isDraining() bool {
	_, draining := s.status()
	return draining
}

func (c *Client) IsClosed() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
	}
	if c.session != nil {
		return c.session.isClosed()
	}
	c.quicConnMu.RLock()
	conn := c.quicConn
	c.quicConnMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
			return true
		default:
		}
	}
	return false
}

// IsHardClosed reports whether the underlying connection is genuinely dead
// (unusable even for streams already in flight), as opposed to merely
// draining after a graceful GOAWAY. Only hard-dead clients should have their
// context canceled — canceling a draining client's context kills every
// active multiplexed stream on it even though HTTP/2 promises those streams
// may run to completion.
func (c *Client) IsHardClosed() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
	}
	if c.session != nil {
		return c.session.isHardClosed()
	}
	c.quicConnMu.RLock()
	conn := c.quicConn
	c.quicConnMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
			return true
		default:
		}
	}
	return false
}

// IsDraining reports whether the client is in a graceful GOAWAY drain: no
// new streams should be routed to it, but existing streams are left alone.
func (c *Client) IsDraining() bool {
	if c.session != nil {
		return c.session.isDraining()
	}
	return false
}

func (c *Client) setQUICConn(conn *quic.Conn) {
	c.quicConnMu.Lock()
	c.quicConn = conn
	c.quicConnMu.Unlock()
}

// EverConnected reports whether this Client ever managed to establish a
// working underlying connection (h2 ClientConn / QUIC conn) at least once,
// as opposed to having failed on its very first dial. Used by
// MultiplexClient to decide whether a retry-on-fresh-client is worth the
// extra full timeout: if we never connected even once, the server/network
// path itself is almost certainly the problem, and dialing yet another fresh
// client at the same destination over the same broken path will just burn a
// second full C.TCPTimeout for an identical failure.
func (c *Client) EverConnected() bool {
	if c.session != nil {
		c.session.mu.Lock()
		defer c.session.mu.Unlock()
		return c.session.clientConn != nil
	}
	c.quicConnMu.RLock()
	defer c.quicConnMu.RUnlock()
	return c.quicConn != nil
}

func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		ctx:           ctx,
		cancel:        cancel,
		server:        options.Server,
		serverString:  options.Server.String(),
		auth:          buildAuth(options.Username, options.Password),
		healthCheck:   options.HealthCheck,
		udpPaddingMin: options.UDPPaddingMin,
		udpPaddingMax: options.UDPPaddingMax,
	}
	if options.QUIC {
		congestionControlFactory, err := congestion.NewCongestionControl(options.CongestionControl, options.CWND, ntp.TimeFuncFromContext(ctx))
		if err != nil {
			cancel()
			return nil, err
		}
		if len(options.TLSConfig.NextProtos()) == 0 {
			options.TLSConfig.SetNextProtos([]string{"h3"})
		}
		client.roundTripper = &http3.Transport{
			QUICConfig: &quic.Config{
				// Оптимизировано для мобильных: чем реже шлём keepalive,
				// тем дольше радиомодуль может простаивать между пакетами
				// вместо постоянного active-состояния. 90s даёт запас под
				// MaxIdleTimeout=2m (не успевает истечь) и втрое реже будит
				// радио, чем прежние 30s. Компромисс: у некоторых мобильных
				// операторов NAT-маппинг для UDP живёт < 90s — тогда между
				// keepalive'ами мэппинг может протухнуть, и следующий пакет
				// потребует пересоздания сессии (это не баг, просто дороже
				// одно переподключение вместо лишних keepalive'ов весь день).
				// Если увидишь рост частоты переподключений — можно вернуть
				// к 30-45s.
				MaxIdleTimeout:  time.Minute * 2,
				KeepAlivePeriod: time.Second * 90,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *stdtls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udpConn, err := options.Dialer.DialContext(ctx, N.NetworkUDP, client.server)
				if err != nil {
					return nil, err
				}
				pktConn := bufio.NewUnbindPacketConn(udpConn)
				var conn *quic.Conn
				if qd, ok := options.TLSConfig.(tls.QUICDialer); ok {
					conn, err = qd.DialEarly(ctx, pktConn, udpConn.RemoteAddr(), cfg)
				} else {
					conn, err = qtls.DialEarly(ctx, pktConn, udpConn.RemoteAddr(), options.TLSConfig, cfg)
				}
				if err != nil {
					return nil, err
				}
				conn.SetCongestionControl(congestionControlFactory(conn))
				client.setQUICConn(conn)
				return conn, nil
			},
		}
	} else {
		if len(options.TLSConfig.NextProtos()) == 0 {
			options.TLSConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		transport := &http2.Transport{
			AllowHTTP: true,
			// Мягкий low-level пинг на уровне HTTP/2: пингуем, только если
			// от сервера не было чтения дольше ReadIdleTimeout (реактивно,
			// а не постоянный heartbeat как у QUIC). 90s вместо 45s — реже
			// лишний раз будим радиомодуль на простаивающем соединении.
			ReadIdleTimeout: time.Second * 90,
			PingTimeout:     time.Second * 15,
		}
		session := &h2Session{
			transport: transport,
			server:    client.server,
			tlsDialer: tls.NewDialer(options.Dialer, options.TLSConfig),
			ctx:       ctx,
			dialMu:    make(chan struct{}, 1),
		}
		transport.ConnPool = session
		client.roundTripper = transport
		client.session = session
	}
	return client, nil
}

func (c *Client) start() {
	if c.healthCheck {
		c.healthCheckTimer = time.NewTimer(DefaultHealthCheckTimeout)
		go c.loopHealthCheck()
	}
}

func (c *Client) loopHealthCheck() {
	consecutiveFailures := 0
	for {
		select {
		case <-c.healthCheckTimer.C:
		case <-c.ctx.Done():
			c.healthCheckTimer.Stop()
			return
		}
		if c.count.Load() > 0 {
			// На клиенте прямо сейчас есть живые стримы — это само по себе
			// доказательство того, что соединение работает. Не гоняем
			// отдельный CONNECT health-check, который на загруженном
			// H2-соединении может ложно упереться в очередь за тем же
			// потоком и словить фантомный таймаут, хотя данные реально идут.
			consecutiveFailures = 0
			c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
			continue
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		err := c.HealthCheck(ctx)
		cancel()
		if err != nil {
			consecutiveFailures++
			// Защита батареи: если первый чек упал, ждем 15 секунд вместо жесткого спама раз в 2 секунды
			if consecutiveFailures < 2 {
				c.healthCheckTimer.Reset(15 * time.Second)
				continue
			}
			_ = c.Close()
			return
		}
		consecutiveFailures = 0
	}
}

func (c *Client) resetHealthCheckTimer() {
	if c.healthCheckTimer == nil {
		return
	}
	c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
}

func (c *Client) roundTrip(request *http.Request, conn *httpConn) {
	c.startOnce.Do(c.start)
	pipeReader, pipeWriter := io.Pipe()
	request.Body = pipeReader
	*conn = httpConn{writer: pipeWriter, created: make(chan struct{})}
	c.count.Add(1)
	conn.closeFn = sync.OnceFunc(func() {
		if c.count.Add(-1) == 0 {
			// Клиент уже помечен мёртвым (health-check/getClient), но пока
			// на нём были активные стримы, мы намеренно не рвали соединение
			// (см. комментарий у cancel ниже). Как только последний стрим
			// реально завершился — дожимаем: закрываем опустевшую
			// TCP-сессию, иначе она повиснет открытой до серверного таймаута.
			select {
			case <-c.ctx.Done():
				if closer, ok := c.roundTripper.(io.Closer); ok {
					_ = closer.Close()
				}
				if t, ok := c.roundTripper.(*http2.Transport); ok {
					t.CloseIdleConnections()
				}
			default:
			}
		}
	})
	// ВАЖНО: контекст запроса намеренно НЕ наследуется от c.ctx.
	// Раньше было ctx, cancel := context.WithCancel(c.ctx) — из-за этого
	// c.cancel() (вызывается из c.Close(), в т.ч. из loopHealthCheck при
	// двух неудачных health-check'ах подряд) мгновенно отменял контексты
	// ВСЕХ активных мультиплексированных стримов на этом h2-соединении
	// разом, даже полностью живых, которые просто не успели ответить на
	// собственный health-check из-за конкуренции за то же H2-соединение.
	// Именно это выглядело как "отваливающийся http2": пачка не связанных
	// между собой стримов к разным хостам падала с context canceled в один
	// и тот же момент. Теперь у запроса свой независимый контекст с
	// единственным источником отмены — вызывающая сторона (conn.Close())
	// и жёсткий таймаут ниже. Смерть/переиспользование Client'а на уровне
	// пула по-прежнему решается через IsHardClosed()/getClient() и влияет
	// только на маршрутизацию НОВЫХ стримов, а не на уже открытые.
	ctx, cancel := context.WithCancel(context.Background())
	conn.cancelFn = cancel
	go func() {
		hardTimeout := time.AfterFunc(C.TCPTimeout, cancel)
		defer hardTimeout.Stop()
		request = request.WithContext(ctx)
		response, err := c.roundTripper.RoundTrip(request)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setup(nil, err)
		} else if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
			_ = pipeWriter.CloseWithError(err)
			_ = pipeReader.CloseWithError(err)
			conn.setup(nil, err)
		} else {
			c.resetHealthCheckTimer()
			conn.setup(response.Body, nil)
		}
	}()
}

func (c *Client) newConnectRequest(host, userAgent string) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: c.serverString},
		Header: http.Header{
			"User-Agent":          {userAgent},
			"Proxy-Authorization": {c.auth},
		},
		Host: host,
	}
}

func (c *Client) Dial(ctx context.Context, host string) (net.Conn, error) {
	conn := &tcpConn{}
	c.roundTrip(c.newConnectRequest(host, tcpUserAgent), &conn.httpConn)
	if err := conn.waitCreated(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn := &clientPacketConn{paddingMin: c.udpPaddingMin, paddingMax: c.udpPaddingMax}
	c.roundTrip(c.newConnectRequest(UDPMagicAddress, udpUserAgent), &conn.httpConn)
	if err := conn.waitCreated(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) Close() error {
	c.cancel()
	if closer, ok := c.roundTripper.(io.Closer); ok {
		_ = closer.Close()
	}
	if t, ok := c.roundTripper.(*http2.Transport); ok {
		t.CloseIdleConnections()
	}
	if c.healthCheckTimer != nil {
		c.healthCheckTimer.Stop()
	}
	return nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	response, err := c.roundTripper.RoundTrip(c.newConnectRequest(HealthCheckMagicAddress, runtime.GOOS).WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}
	return nil
}

// dialFailureBackoff — окно после провала ПЕРВОГО дозвона свежего клиента
// (EverConnected()==false), в течение которого newClientLocked() не плодит
// ЕЩЁ ОДНОГО параллельного кандидата поверх уже идущей попытки. Без этого
// каждый всплеск конкурентных Dial() при недоступном сервере (например,
// пачка приложений реконнектится сразу после смены wifi, а путь до сервера
// в этот момент ещё не поднялся/недоступен) поднимает до maxConnections
// параллельных клиентов одновременно, каждый из которых независимо жрёт
// TCPConnectTimeout (5s) на дозвон к ОДНОМУ И ТОМУ ЖЕ IP сервера — и цикл
// тут же повторяется на следующей волне запросов, раз за разом, пока путь
// не восстановится. Внешне это выглядит как непрерывно "отваливающийся"
// http2-путь, хотя по факту это самонагнетающееся громовое стадо дозвонов,
// а не единичный обрыв. 3s — заметно меньше TCPConnectTimeout, чтобы не
// тормозить настоящее восстановление пути, но достаточно, чтобы схлопнуть
// параллельные попытки в одну серийную, пока сервер действительно недоступен.
const dialFailureBackoff = 3 * time.Second

type MultiplexClient struct {
	// ВАЖНО: раньше здесь был sync.Mutex, и getClient()/forceNewClient()
	// держали его на ВСЁ время реального сетевого дозвона внутри
	// newClientLocked() -> NewClient() (DNS+TCP+TLS, до нескольких секунд
	// на деградировавшей мобильной сети). Проблема не в самой сериализации
	// дозвонов (она даже полезна — не долбим сеть параллельными
	// хендшейками), а в том, что sync.Mutex.Lock() ничем не ограничен: если
	// один вызов Dial() уже дозванивается, все остальные, вставшие в
	// очередь за мьютексом, ждали БЕЗ ТАЙМАУТА и без учёта их собственного
	// ctx — этот простой в очереди вообще не считался ни в C.TCPTimeout, ни
	// в серверный 20s-дедлайн (те начинали тикать только ПОСЛЕ получения
	// мьютекса). Именно поэтому предыдущие правки таймаутов не до конца
	// снимали burst сразу после рестарта: пока сеть ещё не разогналась
	// после холодного старта (характерная для сотовой связи задержка
	// перехода из RRC-idle в connected), первый дозвон мог тянуться, а все
	// остальные стримы копились в очереди сверх любых наших таймаутов.
	// Канал-мьютекс даёт то же самое взаимоисключение, но ожидание можно
	// прервать по ctx вызывающего — стрим отваливается по СВОЕМУ таймауту,
	// а не висит неопределённо долго за чужой спиной.
	mu             chan struct{}
	maxConnections int
	minStreams     int
	maxStreams     int
	ctx            context.Context
	options        ClientOptions
	clients        []*Client
	// backoffUntil — unix-время (наносекунды) до которого newClientLocked()
	// не создаёт НОВЫХ клиентов поверх уже существующих. См. комментарий у
	// dialFailureBackoff. 0 — бэкоффа сейчас нет.
	backoffUntil atomic.Int64
}

// lock ждёт свободный слот мьютекса, но не дольше, чем жив переданный ctx.
func (c *MultiplexClient) lock(ctx context.Context) error {
	select {
	case c.mu <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *MultiplexClient) unlock() {
	<-c.mu
}

func NewMultiplexClient(ctx context.Context, options ClientOptions) (*MultiplexClient, error) {
	maxConnections := options.MaxConnections
	minStreams := options.MinStreams
	maxStreams := options.MaxStreams
	if maxConnections == 0 && minStreams == 0 && maxStreams == 0 {
		maxConnections = 8
		minStreams = 5
	}
	client, err := NewClient(ctx, options)
	if err != nil {
		return nil, err
	}
	mc := &MultiplexClient{
		mu:             make(chan struct{}, 1),
		maxConnections: maxConnections,
		minStreams:     minStreams,
		maxStreams:     maxStreams,
		ctx:            ctx,
		options:        options,
		clients:        []*Client{client},
	}
	// ВАЖНО: без этого пул худел ТОЛЬКО реактивно — pruneIdleClients()
	// вызывался лишь при запросе НОВОГО соединения (newClientLocked).
	// Если приложения разогнали пул до maxConnections штук, а потом трафик
	// стих (экран выключен, телефон в кармане), лишние простаивающие
	// соединения так и оставались открытыми НАВСЕГДА — и каждое из них
	// независимо слало keepalive (QUIC KeepAlivePeriod=30s / H2
	// ReadIdleTimeout=45s), не давая радиомодулю уйти в low-power idle.
	// Раз в минуту принудительно прогоняем ту же логику, что и при
	// демандовом создании клиента, чтобы пул реально сжимался обратно,
	// когда трафика больше нет — экономит батарею в фоне/на паузах.
	go mc.idleReaperLoop()
	return mc, nil
}

func (c *MultiplexClient) idleReaperLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.lock(c.ctx); err != nil {
				return
			}
			c.clients = pruneIdleClients(c.clients)
			c.unlock()
		}
	}
}

func (c *MultiplexClient) Dial(ctx context.Context, host string) (net.Conn, error) {
	primary, err := c.getClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := primary.Dial(ctx, host)
	if err == nil {
		return conn, nil
	}
	// ВАЖНО: раньше isNetworkUnreachable(err) (ENETUNREACH/EHOSTUNREACH —
	// типичный "моргнувший" хендовер вышки/включение мобильных данных на
	// клиенте с auto_detect_interface) сбрасывал ВЕСЬ пул (c.Close()),
	// отменяя контекст каждого Client'а в пуле и тем самым разом обрывая
	// все туннели, которые в этот момент активно передавали данные через
	// другие, полностью исправные соединения пула. Один неудачный дозвон
	// нового стрима не означает, что уже установленные соединения тоже
	// мертвы — их убьёт (и корректно вычистит) getClient()/health-check
	// сам, если интерфейс действительно лёг. Поэтому здесь трогаем только
	// тот единственный клиент, на котором произошёл сбой.
	everConnected := primary.EverConnected()
	c.removeClient(primary)
	if !everConnected {
		// primary ни разу не смог даже установить соединение (первый же
		// дозвон до сервера сдох по таймауту/сети) — сервер или путь до
		// него сейчас попросту недоступны. Ретраить на СВЕЖЕМ клиенте к
		// ТОЙ ЖЕ дестинации по той же дохлой сети — это гарантированно
		// ещё один полный C.TCPTimeout ради идентичного результата
		// (именно так 15s превращались в наблюдаемые 30s на каждый
		// стрим). Отдаём ошибку сразу — вызывающая сторона (роутер,
		// urltest-селектор, сам клиент-приложение) отреагирует быстрее.
		c.noteDialFailure()
		return nil, err
	}
	fresh, freshErr := c.forceNewClient(ctx)
	if freshErr != nil {
		return nil, err
	}
	return fresh.Dial(ctx, host)
}

func (c *MultiplexClient) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	primary, err := c.getClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := primary.ListenPacket(ctx)
	if err == nil {
		return conn, nil
	}
	// See the comment in Dial: never nuke the whole pool over a single
	// failed dial — only the client that actually failed is affected, and
	// we skip the fresh-client retry entirely if this client never had a
	// working connection to begin with (see EverConnected).
	everConnected := primary.EverConnected()
	c.removeClient(primary)
	if !everConnected {
		c.noteDialFailure()
		return nil, err
	}
	fresh, freshErr := c.forceNewClient(ctx)
	if freshErr != nil {
		return nil, err
	}
	return fresh.ListenPacket(ctx)
}

// noteDialFailure запускает окно бэкоффа (см. dialFailureBackoff) после
// провала первого дозвона свежего клиента — на этот период newClientLocked
// перестаёт плодить параллельных кандидатов к тому же (видимо, недоступному)
// серверу.
func (c *MultiplexClient) noteDialFailure() {
	c.backoffUntil.Store(time.Now().Add(dialFailureBackoff).UnixNano())
}

func (c *MultiplexClient) removeClient(dead *Client) {
	_ = c.lock(context.Background())
	for i, t := range c.clients {
		if t == dead {
			c.clients = append(c.clients[:i], c.clients[i+1:]...)
			break
		}
	}
	c.unlock()
	_ = dead.Close()
}

func (c *MultiplexClient) Close() error {
	// Здесь намеренно context.Background(), а не c.ctx: Close() обычно
	// вызывается КАК РАЗ когда c.ctx уже отменён (штатный шатдаун), и если
	// бы ожидание лока было завязано на уже мёртвый ctx, Close() тут же
	// вернул бы ошибку, ничего не закрыв. Закрытие — не пользовательский
	// запрос с дедлайном, ему можно и подождать реальной освобождения лока.
	_ = c.lock(context.Background())
	defer c.unlock()
	var errs []error
	for _, t := range c.clients {
		if err := t.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.clients = nil
	return errors.Join(errs...)
}

func (c *MultiplexClient) getClient(ctx context.Context) (*Client, error) {
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()

	// Вычищаем только по-настоящему мёртвые сессии (IsHardClosed). Сессию в
	// состоянии graceful GOAWAY-дрейна (IsDraining, но не hard-closed) не
	// трогаем и не отменяем её контекст здесь — на ней могут быть активные
	// мультиплексированные стримы, которым HTTP/2 обещал доиграть до конца;
	// раньше это место било IsClosed() (Closed || Closing) и убивало такую
	// сессию целиком при любом обычном GOAWAY/idle-таймауте сервера, разом
	// обрывая все её активные туннели — именно это и выглядело как "вечно
	// отваливающийся" http2-транспорт.
	live := c.clients[:0]
	for _, t := range c.clients {
		if t.IsHardClosed() {
			_ = t.Close()
			continue
		}
		live = append(live, t)
	}
	c.clients = live

	var transport *Client
	for _, t := range c.clients {
		if t.IsDraining() {
			// Дренящаяся сессия не годится для НОВЫХ стримов, но остаётся
			// в пуле нетронутой, пока не станет hard-closed или не опустеет
			// (тогда её приберёт pruneIdleClients/следующий проход выше).
			continue
		}
		if transport == nil || t.count.Load() < transport.count.Load() {
			transport = t
		}
	}
	if transport == nil {
		return c.newClientLocked()
	}
	numStreams := int(transport.count.Load())
	if numStreams == 0 {
		return transport, nil
	}
	if c.maxConnections > 0 {
		if len(c.clients) >= c.maxConnections || numStreams < c.minStreams {
			return transport, nil
		}
	} else if c.maxStreams > 0 && numStreams < c.maxStreams {
		return transport, nil
	}
	return c.newClientLocked()
}

func (c *MultiplexClient) forceNewClient(ctx context.Context) (*Client, error) {
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	return c.newClientLocked()
}

func (c *MultiplexClient) newClientLocked() (*Client, error) {
	c.clients = pruneIdleClients(c.clients)
	// ГЛАВНОЕ: не держим больше ОДНОГО клиента одновременно в состоянии
	// "ещё ни разу не подключался" (EverConnected()==false) — НО только
	// пока во всём пуле нет НИ ОДНОГО клиента, который уже доказал, что
	// путь до сервера жив (EverConnected() && !IsHardClosed()). Раньше
	// это ограничение действовало безусловно, даже когда в пуле уже
	// были рабочие соединения: burst трафика, легитимно требующий
	// scale-up по minStreams/maxConnections (например, 20+ конкурентных
	// стримов от приложения при уже поднятом и здоровом пути), заводил
	// НОВОГО клиента под запись здесь и тут же ловил это правило —
	// каждый следующий стрим, которому тоже нужно было бы поднять свой
	// параллельный клиент, вместо этого вставал в очередь за ЭТИМ ЖЕ
	// единственным "ещё дозванивающимся" клиентом (см. dialMu в
	// h2Session), хотя maxConnections честно разрешал до 8 параллельных
	// соединений. В результате пул не мог разъехаться шире одного
	// коннекшена быстрее, чем успевал завершиться ОДИН TCP+TLS хендшейк
	// за раз — при небыстром хендшейке (RTT до сервера, TLS на CPU,
	// семафор хендшейков на сервере) это и давало волну "operation was
	// canceled" по СВОИМ таймаутам стримов, ждущих очереди на масштаб,
	// хотя сервер был полностью доступен и часть пула уже вовсю работала.
	// Смысл исходной защиты — не долбить параллельными хендшейками
	// сервер, который, возможно, вообще недоступен (холодный старт /
	// путь полностью упал, пул пуст). Как только у нас есть ХОТЯ БЫ ОДИН
	// живой клиент, это уже не тот случай: сервер точно доступен, и
	// параллельный scale-up новыми хендшейками — штатное поведение
	// multiplex, а не громовое стадо в неизвестность.
	hasProvenLiveClient := false
	for _, t := range c.clients {
		if t.EverConnected() && !t.IsHardClosed() {
			hasProvenLiveClient = true
			break
		}
	}
	if !hasProvenLiveClient {
		for _, t := range c.clients {
			if !t.EverConnected() {
				return t, nil
			}
		}
	}
	// Резервный бэкофф на случай, если только что убранный (removeClient)
	// провалившийся клиент уже успел выпасть из пула, а следующий вызов
	// сюда попал раньше, чем noteDialFailure успел от него защититься чем-то
	// другим — не даём тут же родить новый "холодный" клиент вплотную после
	// провала, отдаём последнего оставшегося (если пул не пуст).
	if until := c.backoffUntil.Load(); until != 0 && time.Now().UnixNano() < until && len(c.clients) > 0 {
		return c.clients[len(c.clients)-1], nil
	}
	t, err := NewClient(c.ctx, c.options)
	if err != nil {
		return nil, err
	}
	c.clients = append(c.clients, t)
	return t, nil
}

// maxIdleReserve — сколько простаивающих (count==0) соединений держим
// в резерве при чистке пула, вместо того чтобы закрывать их подчистую.
// Не спасает от burst'а сразу после полного рестарта клиента/сервера
// (там пул стартует с нуля, резервировать нечего) — для этого есть
// серверный семафор на конкурентность handshake'ов. Но помогает в более
// частом случае: пул нарастили под пиковую нагрузку, часть трафика
// затихла, idle-reaper начал его подрезать — а тут снова просыпается
// пачка приложений. Держим 2, а не 1, чтобы такое пробуждение чаще
// попадало на уже тёплое соединение, а не упиралось в холодный дозвон.
const maxIdleReserve = 2

func pruneIdleClients(clients []*Client) []*Client {
	kept := make([]*Client, 0, len(clients))
	idleKeptCount := 0
	for _, t := range clients {
		if t.count.Load() > 0 || idleKeptCount < maxIdleReserve {
			kept = append(kept, t)
			if t.count.Load() == 0 {
				idleKeptCount++
			}
			continue
		}
		_ = t.Close()
	}
	return kept
}
