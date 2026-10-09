package trusttunnel

import (
	"context"
	"io"
)

// closeOnCancel привязывает время жизни стрима к запросу, как соединение
// VLESS привязано к своему сокету: как только клиент сбросил стрим
// (RST_STREAM) или умерло h2/h3-соединение целиком, ctx запроса
// отменяется, и стрим закрывается сразу, не дожидаясь, пока до этого
// дойдёт чтение или запись. Выходит, когда стрим закрылся сам (done).
func closeOnCancel(ctx context.Context, c io.Closer, done <-chan struct{}) {
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
}
