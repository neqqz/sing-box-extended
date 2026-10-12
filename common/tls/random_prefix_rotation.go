package tls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Префикс ClientHello.Random = HMAC(secret, key_share) — уникален для каждого
// handshake (key_share свежий), снаружи неотличим от случайных байт, и НЕ
// зависит от часов клиента. Защита от реплея — ReplayCache на сервере.

// DeriveRotatingRandomPrefixBound вычисляет `length` байт (1-32) из секрета и
// `bind` — сырых байт key_share этого ClientHello. Привязка к key_share нужна,
// чтобы подсмотренный префикс нельзя было вставить в чужой ClientHello:
// атакующий с копией key_share не знает приватного ключа и не расшифрует
// Certificate TLS 1.3.
func DeriveRotatingRandomPrefixBound(secret []byte, length int, bind []byte) []byte {
	if length <= 0 {
		return nil
	}
	if length > 32 {
		length = 32
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("trusttunnel-random-prefix-v3-bound:"))
	// Длина bind префиксом — чтобы конкатенация была однозначной.
	var bindLen [4]byte
	binary.BigEndian.PutUint32(bindLen[:], uint32(len(bind)))
	mac.Write(bindLen[:])
	mac.Write(bind)
	return mac.Sum(nil)[:length]
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
