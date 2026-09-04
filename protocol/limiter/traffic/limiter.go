package traffic

type TrafficLimiter interface {
	Can(n uint64) error
	Add(n uint64) error
}
