//go:build !linux

package trusttunnel

import "net"

// setTCPCongestionControl: TCP_CONGESTION по сокету — Linux-специфичный
// механизм (setsockopt(IPPROTO_TCP, TCP_CONGESTION, ...)). На остальных
// платформах (Windows, macOS/BSD) сравнимого портируемого API нет — тихо
// ничего не делаем и остаёмся на системном congestion control, как и раньше.
func SetTCPCongestionControl(net.Conn, string) {}
