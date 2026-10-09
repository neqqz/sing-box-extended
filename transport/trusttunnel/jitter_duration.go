package trusttunnel

import (
	"math/rand/v2"
	"time"
)

// jitterDuration возвращает base, случайно сдвинутый на ±fraction (0.3 =
// ±30%). Строго периодический трафик (health-check и keepalive ровно раз в
// 7 секунд) — устойчивая сигнатура даже под шифрованием; небольшой разброс
// её размывает, не меняя средней частоты.
func jitterDuration(base time.Duration, fraction float64) time.Duration {
	if base <= 0 || fraction <= 0 {
		return base
	}
	delta := (rand.Float64()*2 - 1) * fraction
	return base + time.Duration(float64(base)*delta)
}
