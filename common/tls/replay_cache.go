package tls

import (
	"sync"
	"time"
)

const (
	replayCacheTTL = time.Hour
	replayCacheMax = 100_000
)

// ReplayCache помнит уже принятые ClientHello.Random. Легитимный клиент не
// повторяет random (key_share свежий), поэтому повтор — реплей. Только в
// памяти: shortcut: после рестарта сервера один перехваченный hello можно
// проиграть один раз; для общего кэша на несколько инстансов нужен внешний store.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: make(map[[32]byte]time.Time)}
}

// Seen возвращает true, если random уже был принят; иначе запоминает его.
// Звать только ПОСЛЕ успешной проверки префикса, иначе мусор вытеснит кэш.
func (c *ReplayCache) Seen(random []byte) bool {
	var key [32]byte
	copy(key[:], random)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[key]; ok && now.Before(exp) {
		return true
	}
	if len(c.seen) >= replayCacheMax {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= replayCacheMax {
			// shortcut: при переполнении живыми записями сбрасываем всё, кэш — best-effort.
			c.seen = make(map[[32]byte]time.Time)
		}
	}
	c.seen[key] = now.Add(replayCacheTTL)
	return false
}
