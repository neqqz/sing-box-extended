package option

type NodeServiceOptions struct {
	UUID               string   `json:"uuid"`
	Inbounds           []string `json:"inbounds"`
	ConnectionLimiters []string `json:"connection_limiters"`
	BandwidthLimiters  []string `json:"bandwidth_limiters"`
	TrafficLimiters    []string `json:"traffic_limiters"`
	RateLimiters       []string `json:"rate_limiters"`
	Manager            string   `json:"manager"`
}
