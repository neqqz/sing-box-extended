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
//
// ВНИМАНИЕ: значение одинаково для ВСЕХ клиентов в течение одного окна и
// само по себе реплеится в самодельный ClientHello (см. подробности в
// DeriveRotatingRandomPrefixBound). Для TCP/H2-пути (common/tls/utls_client.go,
// transport/trusttunnel/prefix_listener.go) эта функция больше не
// используется — используйте DeriveRotatingRandomPrefixBound. Здесь
// оставлена только для QUIC-пути (protocol/trusttunnel/inbound.go), пока
// у форка sagernet/quic-go (внешний репозиторий, не в этом дереве) не
// прокинут key_share в ServerClientRandomVerify — см. TODO в inbound.go.
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

// DeriveRotatingRandomPrefixBound — то же самое, что DeriveRotatingRandomPrefix,
// но дополнительно привязывает результат к `bind` — данным, уникальным для
// ИМЕННО ЭТОГО handshake (сырые байты key_share extension из этого конкретного
// ClientHello). Это закрывает реальную дыру, которой подвержена небиндящая
// версия: ClientHello.Random передаётся открытым текстом, а
// DeriveRotatingRandomPrefix зависит только от (secret, window) — то есть
// ОДНО И ТО ЖЕ значение для всех клиентов в течение ~60 секунд. Значит, кто
// угодно, пассивно наблюдающий хотя бы одно легитимное соединение (для
// state-level DPI вроде ТСПУ — это вообще всегда), может взять это значение
// и вставить в СВОЙ собственный, с нуля собранный ClientHello (со своим
// key_share, остальными полями — чем угодно). Раз этот подделанный ClientHello
// в остальном полностью соответствует спецификации, пин TLS-версии тут не
// спасает: атакующий проходит полностью легитимный TLS 1.3 handshake своими
// ключами и без проблем расшифровывает настоящий сертификат сервера.
//
// Привязка к key_share это чинит: атакующий, подставивший подсмотренное
// значение (secret,window) к СВОЕМУ key_share, не пройдёт проверку вообще
// (ожидаемое значение для его key_share другое, а secret он не знает).
// Атакующий, который вместо этого дословно скопирует ещё и key_share из
// подсмотренного соединения (чтобы проверка прошла), не владеет приватным
// ключом, соответствующим этому публичному значению — соответственно не
// может вычислить handshake traffic secret TLS 1.3 и расшифровать
// зашифрованный Certificate от сервера: увидит только шифротекст, не
// сертификат.
func DeriveRotatingRandomPrefixBound(secret []byte, length int, window int64, bind []byte) []byte {
	if length <= 0 {
		return nil
	}
	if length > 32 {
		length = 32
	}
	var windowBytes [8]byte
	binary.BigEndian.PutUint64(windowBytes[:], uint64(window))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("trusttunnel-random-prefix-v2-bound:"))
	mac.Write(windowBytes[:])
	// Длина bind префиксом — чтобы конкатенация (window_bytes || bind) не была
	// неоднозначной относительно (window_bytes || bind') разной длины.
	var bindLen [4]byte
	binary.BigEndian.PutUint32(bindLen[:], uint32(len(bind)))
	mac.Write(bindLen[:])
	mac.Write(bind)
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
