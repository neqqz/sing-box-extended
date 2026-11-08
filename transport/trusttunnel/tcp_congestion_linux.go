//go:build linux

package trusttunnel

import (
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetTCPCongestionControl выставляет TCP_CONGESTION на сыром TCP-сокете.
//
// ВАЖНО: поля CongestionController/CWND в option.TrustTunnelInboundOptions/OutboundOptions
// применяются и к QUIC-транспорту (userspace BBR/Cubic), и к обычному H2/TCP-пути.
//
// При указании bbr2, bbr3 или вариантов bbr функция сначала пробует выставить
// запрошенный алгоритм у ядра Linux. Если ядро не содержит отдельного модуля с
// таким именем (например, в стандартном ядре Ubuntu, где bbr единый), происходит
// мягкий откат на штатный "bbr" ядра. Ошибку намеренно не считаем фатальной:
// если алгоритм недоступен, соединение остаётся на системном дефолте.
func SetTCPCongestionControl(conn net.Conn, name string) {
	if name == "" || conn == nil {
		return
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return
	}
	algo := strings.ToLower(name)
	_ = rawConn.Control(func(fd uintptr) {
		err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, algo)
		if err != nil && strings.HasPrefix(algo, "bbr") && algo != "bbr" {
			_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
		}
	})
}
