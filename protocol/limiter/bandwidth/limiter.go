package bandwidth

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/list"
)

type BandwidthLimiter interface {
	WaitN(ctx context.Context, n int) (err error)
	SetSpeed(speed uint64)
}

type FairQueueLimiter struct {
	limiter      BandwidthLimiter
	connIDGetter ConnIDGetter

	flows *list.List[*flow]
	index map[string]*list.Element[*flow]
	bytes map[string]uint64
	pool  sync.Pool
	queue chan struct{}
	reset time.Time

	mtx sync.Mutex
}

func NewFairQueueLimiter(connIDGetter ConnIDGetter, limiter BandwidthLimiter) *FairQueueLimiter {
	return &FairQueueLimiter{
		limiter:      limiter,
		connIDGetter: connIDGetter,
		flows:        list.New[*flow](),
		index:        make(map[string]*list.Element[*flow]),
		bytes:        make(map[string]uint64),
		pool:         sync.Pool{New: func() any { return list.New[*request]() }},
		queue:        make(chan struct{}, 1),
		reset:        time.Now().Add(time.Second),
	}
}

func (l *FairQueueLimiter) SetSpeed(speed uint64) {
	l.limiter.SetSpeed(speed)
}

func (l *FairQueueLimiter) WaitN(ctx context.Context, n int) error {
	id, _ := l.connIDGetter(ctx, adapter.ContextFrom(ctx))
	mainRequest := &request{ctx: ctx, done: make(chan struct{}), n: n}
	l.mtx.Lock()
	elem, ok := l.index[id]
	if !ok {
		f := &flow{id: id, pending: l.pool.Get().(*list.List[*request])}
		elem = l.flows.PushFront(f)
		l.index[id] = elem
	}
	mainRequestElem := elem.Value.pending.PushBack(mainRequest)
	l.reorder(elem)
	l.mtx.Unlock()
	select {
	case l.queue <- struct{}{}:
	case <-mainRequest.done:
		return nil
	case <-ctx.Done():
		l.mtx.Lock()
		l.removeRequest(id, mainRequestElem)
		l.mtx.Unlock()
		return ctx.Err()
	}
	select {
	case <-mainRequest.done:
		<-l.queue
		return nil
	default:
	}
	for {
		if ctx.Err() != nil {
			l.mtx.Lock()
			l.removeRequest(id, mainRequestElem)
			l.mtx.Unlock()
			<-l.queue
			return ctx.Err()
		}
		l.mtx.Lock()
		now := time.Now()
		if l.reset.Compare(now) == -1 {
			clear(l.bytes)
			l.reset = now.Add(time.Second)
		}
		flowElem := l.flows.Front()
		flow := flowElem.Value
		firstRequestElem := flow.pending.Front()
		firstRequest := firstRequestElem.Value
		l.bytes[flow.id] += uint64(firstRequest.n)
		firstRequestElem.Remove()
		if flow.pending.Len() == 0 {
			l.flows.Remove(flowElem)
			delete(l.index, flow.id)
			l.pool.Put(flow.pending)
		} else {
			l.reorder(flowElem)
		}
		l.mtx.Unlock()
		l.limiter.WaitN(firstRequest.ctx, firstRequest.n)
		close(firstRequest.done)
		if firstRequest == mainRequest {
			<-l.queue
			return nil
		}
	}
}

func (l *FairQueueLimiter) reorder(elem *list.Element[*flow]) {
	f := elem.Value
	front := f.pending.Front()
	if front == nil {
		return
	}
	cost := l.bytes[f.id] + uint64(front.Value.n)
	for e := l.flows.Front(); e != nil; e = e.Next() {
		if e == elem {
			continue
		}
		eFront := e.Value.pending.Front()
		if eFront == nil {
			continue
		}
		if cost < l.bytes[e.Value.id]+uint64(eFront.Value.n) {
			l.flows.MoveBefore(elem, e)
			return
		}
	}
	l.flows.MoveToBack(elem)
}

func (l *FairQueueLimiter) removeRequest(id string, elem *list.Element[*request]) {
	if !elem.Remove() {
		return
	}
	if flowElem, ok := l.index[id]; ok && flowElem.Value.pending.Len() == 0 {
		l.flows.Remove(flowElem)
		delete(l.index, id)
		l.pool.Put(flowElem.Value.pending)
	}
}

type flow struct {
	id      string
	pending *list.List[*request]
}

type request struct {
	ctx  context.Context
	done chan struct{}
	n    int
}
