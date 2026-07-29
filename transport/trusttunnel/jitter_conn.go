package trusttunnel

import (
	"math/rand"
	"net"
	"time"
)

// jitterConn — обёртка над net.Conn, добавляющая случайную задержку перед
// каждым Write(). Цель — разрушить статистику интервалов между исходящими
// пакетами, по которой DPI (даже без разбора содержимого) может отличать
// VPN/прокси-протокол от обычного HTTPS: у настоящего браузера тайминги
// пакетов рваные и завязаны на события UI/рендеринга, а у прокси, гоняющего
// данные туда-сюда без пауз, интервалы между записями часто куда регулярнее
// и однороднее — это само по себе статистический отпечаток.
//
// ВАЖНО: это прямой trade-off с задержкой. h2 пишет все замультиплексированные
// стримы через один writer, так что джиттер добавляется на КАЖДЫЙ Write —
// то есть на каждый HTTP/2-фрейм на этом соединении, а не один раз на
// соединение. При minMs=0 maxMs=0 (дефолт) обёртка не добавляет никакой
// задержки и эквивалентна отсутствию обёртки.
type jitterConn struct {
	net.Conn
	minMs int
	maxMs int
}

// NewJitterConn оборачивает conn джиттером, если maxMs > 0; иначе возвращает
// conn как есть (без обёртки, без накладных расходов).
func NewJitterConn(conn net.Conn, minMs, maxMs int) net.Conn {
	if maxMs <= 0 || maxMs < minMs {
		return conn
	}
	if minMs < 0 {
		minMs = 0
	}
	return &jitterConn{Conn: conn, minMs: minMs, maxMs: maxMs}
}

func (c *jitterConn) Write(b []byte) (int, error) {
	spread := c.maxMs - c.minMs
	delayMs := c.minMs
	if spread > 0 {
		delayMs += rand.Intn(spread + 1) //nolint:gosec // не крипто-контекст, просто тайминг-шум
	}
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	return c.Conn.Write(b)
}

// jitterPacketConn — то же самое, что jitterConn, но для net.PacketConn
// (QUIC-путь ходит через WriteTo на UDP-сокете, а не через Write на
// потоковом TCP-соединении). ВАЖНО: в отличие от TCP, где ядро само решает
// вопросы ретрансмиссии/ACK независимо от момента вызова Write(), у QUIC
// congestion control (BBR/cubic в quic-go) сам меряет RTT/bandwidth по
// факту фактического времени отправки пакета — внешний джиттер поверх уже
// существующего пейсинга quic-go добавляет шум и в эти замеры, а не только
// в задержку. Используйте меньшие значения, чем для H2, и смотрите на
// throughput внимательнее.
type jitterPacketConn struct {
	net.PacketConn
	minMs int
	maxMs int
}

// NewJitterPacketConn оборачивает conn джиттером, если maxMs > 0; иначе
// возвращает conn как есть.
func NewJitterPacketConn(conn net.PacketConn, minMs, maxMs int) net.PacketConn {
	if maxMs <= 0 || maxMs < minMs {
		return conn
	}
	if minMs < 0 {
		minMs = 0
	}
	return &jitterPacketConn{PacketConn: conn, minMs: minMs, maxMs: maxMs}
}

func (c *jitterPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	spread := c.maxMs - c.minMs
	delayMs := c.minMs
	if spread > 0 {
		delayMs += rand.Intn(spread + 1) //nolint:gosec
	}
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	return c.PacketConn.WriteTo(b, addr)
}
