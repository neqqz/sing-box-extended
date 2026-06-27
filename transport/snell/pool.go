package snell

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

// poolEntry holds a pooled item with its insertion time.

// connPool is a small connection pool with age-based eviction.

// milliseconds

// Pool is a pool of reusable snell connections.
type Pool struct {
	pool *connPool
}

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	elm, err := p.pool.GetContext(ctx)
	if err != nil {
		return nil, err
	}
	return &PoolConn{Snell: elm, pool: p}, nil
}

func (p *Pool) Put(conn *Snell) {
	if err := HalfClose(conn); err != nil {
		_ = conn.Close()
		return
	}
	p.pool.put(conn)
}

// PoolConn wraps a pooled snell connection and returns it to the pool on Close.
type PoolConn struct {
	*Snell
	pool           *Pool
	closeWriteOnce sync.Once
	closeWriteErr  error
	closeOnce      sync.Once
	closeErr       error
}

func (pc *PoolConn) Read(b []byte) (int, error) {
	n, err := pc.Snell.Read(b)
	if err == ErrZeroChunk {
		return n, io.EOF
	}
	return n, err
}

func (pc *PoolConn) Write(b []byte) (int, error) {
	return pc.Snell.Write(b)
}

func (pc *PoolConn) CloseWrite() error {
	pc.closeWriteOnce.Do(func() {
		pc.closeWriteErr = writeZeroChunk(pc.Snell)
	})
	return pc.closeWriteErr
}

func (pc *PoolConn) Close() error {
	pc.closeOnce.Do(func() {
		if err := pc.CloseWrite(); err != nil {
			pc.closeErr = err
			_ = pc.Snell.Close()
			return
		}
		_ = pc.Snell.Conn.SetReadDeadline(time.Time{})
		pc.Snell.reply = false
		pc.pool.pool.put(pc.Snell)
	})
	return pc.closeErr
}

// NewPool creates a new snell connection pool using the given factory.
func NewPool(factory func(context.Context) (*Snell, error)) *Pool {
	cp := &connPool{
		ch:      make(chan *poolEntry, 10),
		factory: factory,
		maxAge:  15000,
		evict: func(item *Snell) {
			_ = item.Close()
		},
	}
	p := &Pool{pool: cp}
	runtime.SetFinalizer(p, recycle)
	return p
}

type poolEntry struct {
	elm  *Snell
	time time.Time
}

type connPool struct {
	ch      chan *poolEntry
	factory func(context.Context) (*Snell, error)
	evict   func(*Snell)
	maxAge  int64
}

func (p *connPool) GetContext(ctx context.Context) (*Snell, error) {
	now := time.Now()
	for {
		select {
		case item := <-p.ch:
			if p.maxAge != 0 && now.Sub(item.time).Milliseconds() > p.maxAge {
				if p.evict != nil {
					p.evict(item.elm)
				}
				continue
			}
			return item.elm, nil
		default:
			return p.factory(ctx)
		}
	}
}

func (p *connPool) put(item *Snell) {
	e := &poolEntry{
		elm:  item,
		time: time.Now(),
	}
	select {
	case p.ch <- e:
		return
	default:
		if p.evict != nil {
			p.evict(item)
		}
		return
	}
}

func recycle(p *Pool) {
	for item := range p.pool.ch {
		if p.pool.evict != nil {
			p.pool.evict(item.elm)
		}
	}
}
