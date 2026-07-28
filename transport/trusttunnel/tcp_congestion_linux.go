//go:build linux

package trusttunnel

import (
	"net"

	"golang.org/x/sys/unix"
)

// linuxCongestionControlName сопоставляет имена congestion_controller,
// принятые для QUIC-режима (см. common/congestion/congestion.go — там это
// userspace-реализации из sing-quic), с реальными именами модулей ядра
// Linux (net.ipv4.tcp_available_congestion_control). У ядра нет
// "bbr_standard"/"bbr2_variant" — это варианты конкретно userspace-BBR из
// sing-quic под QUIC, для обычного TCP-сокета ближайший и единственный
// осмысленный аналог — штатный "bbr" ядра.
func linuxCongestionControlName(name string) string {
	switch name {
	case "bbr2":
		return "bbr2"
	case "reno":
		return "reno"
	case "cubic":
		return "cubic"
	case "", "bbr", "bbr_standard", "bbr2_variant":
		return "bbr"
	default:
		return "bbr"
	}
}

// setTCPCongestionControl выставляет TCP_CONGESTION на сыром TCP-сокете.
//
// ВАЖНО: до этого фикса поля CongestionController/CWND в
// option.TrustTunnelInboundOptions/OutboundOptions применялись ТОЛЬКО к
// QUIC-транспорту (см. common/congestion/congestion.go, вызывается из
// transport/trusttunnel/client.go:447 и protocol/trusttunnel/inbound.go:314) —
// у H2/TCP-пути своего congestion control нет вообще, он полностью отдан на
// откуп дефолту ядра (обычно cubic на Linux). Cubic реагирует на любую
// потерю резким и медленно восстанавливающимся сокращением окна — на
// маршруте с заметным RTT и хотя бы небольшим фоновым лоссом (типичный
// зарубежный VPS + DPI-зажатый канал) это и даёт систематически более
// низкую throughput у H2-режима трасттуннеля по сравнению с QUIC-режимом,
// где тот же самый congestion_controller (BBR по умолчанию) настоящий.
// Эта функция закрывает именно этот разрыв: тот же конфиг-параметр
// начинает действовать и на H2-пути тоже.
//
// Не требует root — только чтобы алгоритм уже был встроен/загружен в ядро
// (net.ipv4.tcp_available_congestion_control) и не был исключён
// net.ipv4.tcp_allowed_congestion_control. Ошибку намеренно не считаем
// фатальной для соединения: если алгоритм недоступен, просто остаёмся на
// системном дефолте — как и было до этого фикса, просто без деградации.
func SetTCPCongestionControl(conn net.Conn, name string) {
	if name == "" {
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
	algo := linuxCongestionControlName(name)
	_ = rawConn.Control(func(fd uintptr) {
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, algo)
	})
}
