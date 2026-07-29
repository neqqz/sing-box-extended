package tls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Пакет для одной задачи: заменить статичный client_random_prefix
// (одни и те же байты на КАЖДОМ соединении — удобная фиксированная сигнатура
// для DPI, делающей полную пересборку TCP-потока и накапливающей статистику
// по многим соединениям от одного клиента/сервера) на значение, которое
// меняется каждые несколько десятков секунд и который невозможно
// предсказать/воспроизвести без общего секрета.
//
// Обе стороны (клиент при отправке ClientHello.Random, сервер при проверке)
// вызывают DeriveRotatingRandomPrefix независимо, с одним и тем же secret —
// это не handshake, просто детерминированная функция от времени, так что
// дополнительного round-trip не нужно.

const defaultRandomPrefixWindowSeconds = 60

// RandomPrefixWindowSeconds возвращает windowSeconds, или дефолт 60, если
// windowSeconds <= 0 (означает "не задано" в конфиге).
func RandomPrefixWindowSeconds(windowSeconds int) int64 {
	if windowSeconds <= 0 {
		return defaultRandomPrefixWindowSeconds
	}
	return int64(windowSeconds)
}

// CurrentRandomPrefixWindow — номер текущего окна ротации для данного unix-времени.
func CurrentRandomPrefixWindow(nowUnix int64, windowSeconds int) int64 {
	ws := RandomPrefixWindowSeconds(windowSeconds)
	return nowUnix / ws
}

// DeriveRotatingRandomPrefix детерминированно вычисляет `length` байт
// (1-32) для данного окна `window` из общего секрета `secret`. Результат
// неотличим от случайных байт для любого, кто не знает secret (это прямой
// вывод HMAC-SHA256), и полностью меняется на следующем окне.
func DeriveRotatingRandomPrefix(secret []byte, length int, window int64) []byte {
	if length <= 0 {
		return nil
	}
	if length > 32 {
		length = 32
	}
	var windowBytes [8]byte
	binary.BigEndian.PutUint64(windowBytes[:], uint64(window))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("trusttunnel-random-prefix-v1:"))
	mac.Write(windowBytes[:])
	sum := mac.Sum(nil)
	return sum[:length]
}

// RandomPrefixLenOrDefault возвращает prefixLen, или дефолт 8, если prefixLen <= 0.
func RandomPrefixLenOrDefault(prefixLen int) int {
	if prefixLen <= 0 {
		return 8
	}
	if prefixLen > 32 {
		return 32
	}
	return prefixLen
}
