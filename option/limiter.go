package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type BandwidthLimiterOutboundOptions struct {
	Strategy       string                          `json:"strategy"`
	ConnectionType string                          `json:"connection_type,omitempty"`
	Mode           string                          `json:"mode"`
	FlowKeys       []string                        `json:"flow_keys,omitempty"`
	Speed          *byteformats.NetworkBytesCompat `json:"speed"`
	Users          []BandwidthLimiterUser          `json:"users,omitempty"`
	Route          RouteOptions                    `json:"route"`
}

type BandwidthLimiterUser struct {
	Name           string                          `json:"name"`
	Strategy       string                          `json:"strategy"`
	ConnectionType string                          `json:"connection_type,omitempty"`
	Mode           string                          `json:"mode"`
	Speed          *byteformats.NetworkBytesCompat `json:"speed"`
}

type TrafficLimiterOutboundOptions struct {
	Strategy string               `json:"strategy"`
	Mode     string               `json:"mode"`
	Total    *byteformats.Bytes   `json:"total"`
	Users    []TrafficLimiterUser `json:"users,omitempty"`
	Route    RouteOptions         `json:"route"`
}

type TrafficLimiterUser struct {
	Name     string             `json:"name"`
	Strategy string             `json:"strategy"`
	Mode     string             `json:"mode"`
	Total    *byteformats.Bytes `json:"total"`
}

type ConnectionLimiterOutboundOptions struct {
	Strategy       string                  `json:"strategy"`
	ConnectionType string                  `json:"connection_type,omitempty"`
	Count          uint32                  `json:"count"`
	Users          []ConnectionLimiterUser `json:"users,omitempty"`
	Route          RouteOptions            `json:"route"`
}

type ConnectionLimiterUser struct {
	Name           string `json:"name"`
	Strategy       string `json:"strategy"`
	ConnectionType string `json:"connection_type,omitempty"`
	Count          uint32 `json:"count"`
}

type RateLimiterOutboundOptions struct {
	Strategy       string             `json:"strategy"`
	ConnectionType string             `json:"connection_type,omitempty"`
	Count          uint32             `json:"count"`
	Interval       badoption.Duration `json:"interval"`
	Users          []RateLimiterUser  `json:"users,omitempty"`
	Route          RouteOptions       `json:"route"`
}

type RateLimiterUser struct {
	Name           string             `json:"name"`
	Strategy       string             `json:"strategy"`
	ConnectionType string             `json:"connection_type,omitempty"`
	Count          uint32             `json:"count"`
	Interval       badoption.Duration `json:"interval"`
}

type FairQueueOutboundOptions struct {
	FlowKeys []string `json:"flow_keys,omitempty"`
	Outbound string   `json:"outbound"`
}
