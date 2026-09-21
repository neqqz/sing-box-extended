package tls

import (
	"crypto/subtle"
	"encoding/hex"
	"math/rand/v2"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// RandomPrefix — один статичный префикс ClientHello.Random с необязательной
// битовой маской. Формат в конфиге: "hex" или "hex/mask_hex".
type RandomPrefix struct {
	Prefix []byte
	// Mask == nil означает «все биты» (0xff на каждый байт префикса).
	// Если задана — len(Mask) == len(Prefix).
	Mask []byte
}

// FullMask возвращает маску явно: заданную или 0xff × len(Prefix).
func (p RandomPrefix) FullMask() []byte {
	if p.Mask != nil {
		return p.Mask
	}
	mask := make([]byte, len(p.Prefix))
	for i := range mask {
		mask[i] = 0xff
	}
	return mask
}

// Match сообщает, начинается ли random с этого префикса (с учётом маски).
func (p RandomPrefix) Match(random []byte) bool {
	if len(random) < len(p.Prefix) {
		return false
	}
	for i, b := range p.Prefix {
		mask := byte(0xff)
		if i < len(p.Mask) {
			mask = p.Mask[i]
		}
		if random[i]&mask != b&mask {
			return false
		}
	}
	return true
}

// ParseRandomPrefixes разбирает список записей client_random_prefix.
// Пустые строки пропускаются — так старые конфиги с "client_random_prefix": ""
// продолжают означать «не задано». Каждая непустая запись: "hex" или
// "hex/mask_hex", 1–32 байта, длина маски равна длине префикса.
func ParseRandomPrefixes(raw []string) ([]RandomPrefix, error) {
	var result []RandomPrefix
	for _, entry := range raw {
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "/", 2)
		prefix, err := hex.DecodeString(parts[0])
		if err != nil {
			return nil, E.Cause(err, "client_random_prefix: invalid hex")
		}
		if len(prefix) == 0 || len(prefix) > 32 {
			return nil, E.New("client_random_prefix: must be 1-32 bytes")
		}
		item := RandomPrefix{Prefix: prefix}
		if len(parts) == 2 {
			item.Mask, err = hex.DecodeString(parts[1])
			if err != nil {
				return nil, E.Cause(err, "client_random_prefix: invalid mask hex")
			}
			if len(item.Mask) != len(prefix) {
				return nil, E.New("client_random_prefix: mask length must equal prefix length")
			}
		}
		result = append(result, item)
	}
	return result, nil
}

// MatchAnyRandomPrefix — true, если random подходит хотя бы под один префикс.
func MatchAnyRandomPrefix(list []RandomPrefix, random []byte) bool {
	for _, item := range list {
		if item.Match(random) {
			return true
		}
	}
	return false
}

// PickRandomPrefix выбирает случайную запись из непустого списка. Вызывать
// на КАЖДОМ соединении: смысл списка — чтобы у разных соединений одного
// клиента начало ClientHello.Random не было одним и тем же.
func PickRandomPrefix(list []RandomPrefix) RandomPrefix {
	if len(list) == 1 {
		return list[0]
	}
	return list[rand.IntN(len(list))]
}

// HasNonEmpty сообщает, есть ли в списке хотя бы одна непустая строка.
// Пустые записи игнорируются везде (см. ParseRandomPrefixes), поэтому
// "client_random_prefix_secret": "" по-прежнему означает «не задано».
func HasNonEmpty(list []string) bool {
	for _, entry := range list {
		if entry != "" {
			return true
		}
	}
	return false
}

// ParseRandomPrefixSecrets разбирает список hex-секретов для ротации
// префикса (client_random_prefix_secret). Пустые строки пропускаются.
func ParseRandomPrefixSecrets(raw []string) ([][]byte, error) {
	var result [][]byte
	for _, entry := range raw {
		if entry == "" {
			continue
		}
		secret, err := hex.DecodeString(entry)
		if err != nil {
			return nil, E.Cause(err, "client_random_prefix_secret: invalid hex")
		}
		result = append(result, secret)
	}
	return result, nil
}

// PickRandomPrefixSecret выбирает случайный секрет из непустого списка
// (на клиенте обычно ровно один — свой; список нужен серверу).
func PickRandomPrefixSecret(list [][]byte) []byte {
	if len(list) == 1 {
		return list[0]
	}
	return list[rand.IntN(len(list))]
}

// MatchRotatingRandomPrefixBound — серверная проверка ротирующегося префикса:
// true, если random начинается с префикса, выведенного из ЛЮБОГО из secrets
// для текущего окна или одного из соседних (±1, допуск на рассинхрон часов),
// с привязкой к bind (key_share этого handshake). См.
// DeriveRotatingRandomPrefixBound. Стоимость — 3 HMAC-SHA256 на секрет.
func MatchRotatingRandomPrefixBound(secrets [][]byte, length int, windowSeconds int, random, bind []byte, nowUnix int64) bool {
	if length > 32 {
		length = 32
	}
	if length <= 0 || len(random) < length {
		return false
	}
	now := CurrentRandomPrefixWindow(nowUnix, windowSeconds)
	for _, secret := range secrets {
		for _, window := range [3]int64{now - 1, now, now + 1} {
			expected := DeriveRotatingRandomPrefixBound(secret, length, window, bind)
			if subtle.ConstantTimeCompare(random[:length], expected) == 1 {
				return true
			}
		}
	}
	return false
}
