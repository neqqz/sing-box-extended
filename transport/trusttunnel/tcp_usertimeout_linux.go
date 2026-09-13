//go:build linux

package trusttunnel

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultTCPUserTimeout — см. SetTCPUserTimeout. Выбрано на глаз как
// компромисс: заметно быстрее, чем дефолт ядра (десятки минут), но не
// настолько агрессивно, чтобы рвать соединение на обычной кратковременной
// (несколько секунд) просадке мобильной сети при хендовере между вышками.
// Примерно 2x DefaultHealthCheckTimeout (7s) — так активный health-check
// и TCP_USER_TIMEOUT ловят зависшее соединение примерно в одном порядке
// величины, а не один сильно раньше другого.
const DefaultTCPUserTimeout = 15 * time.Second

// SetTCPUserTimeout выставляет TCP_USER_TIMEOUT на сыром TCP-сокете.
//
// Проблема, которую это закрывает (см. комментарий у IdleTimeout в
// protocol/trusttunnel/inbound.go и getClient() в client.go): на мобильных
// сетях (carrier NAT) путь может сдохнуть молча, без FIN/RST — просто
// перестают доходить пакеты — ПОКА по соединению идёт активная передача
// (например, грузится видео). Ни серверный h2 IdleTimeout (ловит только
// НОЛЬ активных стримов), ни TCP keepalive (Go's KeepAlivePeriod — это
// TCP_KEEPIDLE; TCP_KEEPINTVL/TCP_KEEPCNT остаются дефолтными от ядра —
// на Linux обычно 75s×9, итого ~11 минут до реального обнаружения, и то
// только если соединение простаивает, а не блокировано на записи) этот
// случай не ловят. TCP_USER_TIMEOUT — единственный из трёх примитивов,
// который реагирует именно на "есть неподтверждённые данные в полёте, и
// подтверждения не приходят" — то есть на ровно тот сценарий, который тут
// нужен: сокет с зависшей записью получит ETIMEDOUT за DefaultTCPUserTimeout
// секунд вместо десятков минут, и retry-логика (MultiplexClient на клиенте,
// обработчик стрима на сервере) сможет отреагировать сразу, а не после
// того, как ядро наконец сдастся само.
//
// В отличие от TCP_KEEPIDLE/INTVL/CNT, TCP_USER_TIMEOUT не тикает на
// простаивающем (idle, без данных в полёте) соединении вообще — это не
// замена keepalive, а именно про "запись зависла", что и требуется.
//
// Не требует root. Ошибку намеренно не считаем фатальной для соединения:
// если платформа/ядро не поддерживает опцию, просто остаёмся на дефолте
// ядра, как и было раньше.
func SetTCPUserTimeout(conn net.Conn, d time.Duration) {
	if d <= 0 {
		return
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return
	}
	millis := int(d.Milliseconds())
	_ = rawConn.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, millis)
	})
}
