package constant

import "time"

type Squad struct {
	ID        int       `json:"id" validate:"required"`
	Name      string    `json:"name" validate:"required"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
	UpdatedAt time.Time `json:"updated_at" validate:"required"`
}

type DeletedSquad struct {
	Squad                        Squad
	OrphanedNodeUUIDs            []string
	OrphanedConnectionLimiterIDs []int
	OrphanedTrafficLimiterIDs    []int
	SurvivingNodeUUIDs           []string
}

type SquadCreate struct {
	Name string `json:"name" validate:"required"`
}

type SquadUpdate struct {
	Name string `json:"name" validate:"required"`
}

type Node struct {
	UUID      string    `json:"uuid" validate:"required,uuid4"`
	Name      string    `json:"name" validate:"required"`
	SquadIDs  []int     `json:"squad_ids" validate:"required,min=1"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
	UpdatedAt time.Time `json:"updated_at" validate:"required"`
}

type NodeCreate struct {
	UUID     string `json:"uuid" validate:"required,uuid4"`
	Name     string `json:"name" validate:"required"`
	SquadIDs []int  `json:"squad_ids" validate:"required,min=1"`
}

type NodeUpdate struct {
	Name string `json:"name" validate:"required"`
}

type BaseNode struct {
	UUID string `json:"uuid" validate:"required,uuid4"`
	Name string `json:"name" validate:"required"`
}

type User struct {
	ID             int       `json:"id" validate:"required"`
	SquadIDs       []int     `json:"squad_ids" validate:"required,min=1"`
	Username       string    `json:"username" validate:"required"`
	Inbound        string    `json:"inbound" validate:"required"`
	Type           string    `json:"type" validate:"required"`
	UUID           string    `json:"uuid" validate:"required"`
	Password       string    `json:"password" validate:"required"`
	Secret         string    `json:"secret" validate:"required"`
	AuthorizedKeys []string  `json:"authorized_keys" validate:"omitempty"`
	Flow           string    `json:"flow" validate:"required"`
	AlterID        int       `json:"alter_id" validate:"required"`
	CreatedAt      time.Time `json:"created_at" validate:"required"`
	UpdatedAt      time.Time `json:"updated_at" validate:"required"`
}

type UserCreate struct {
	SquadIDs       []int    `json:"squad_ids" validate:"required,min=1"`
	Username       string   `json:"username" validate:"required"`
	Inbound        string   `json:"inbound" validate:"required"`
	Type           string   `json:"type" validate:"required,oneof=anytls http hysteria hysteria2 mixed mtproxy naive socks ssh trojan trusttunnel tuic vless vmess"`
	UUID           string   `json:"uuid" validate:"omitempty,uuid4"`
	Password       string   `json:"password" validate:"omitempty"`
	Secret         string   `json:"secret" validate:"omitempty"`
	AuthorizedKeys []string `json:"authorized_keys" validate:"omitempty"`
	Flow           string   `json:"flow" validate:"omitempty"`
	AlterID        int      `json:"alter_id" validate:"omitempty"`
}

type UserUpdate struct {
	UUID           string   `json:"uuid" validate:"omitempty,uuid4"`
	Password       string   `json:"password" validate:"omitempty"`
	Secret         string   `json:"secret" validate:"omitempty"`
	AuthorizedKeys []string `json:"authorized_keys" validate:"omitempty"`
	Flow           string   `json:"flow" validate:"omitempty"`
	AlterID        int      `json:"alter_id" validate:"omitempty"`
}

type BaseUser struct {
	UUID           string   `json:"uuid" validate:"omitempty,uuid4"`
	Password       string   `json:"password" validate:"omitempty"`
	Secret         string   `json:"secret" validate:"omitempty"`
	AuthorizedKeys []string `json:"authorized_keys" validate:"omitempty"`
	Flow           string   `json:"flow" validate:"omitempty"`
	AlterID        int      `json:"alter_id" validate:"omitempty"`
}

type ConnectionLimiter struct {
	ID             int       `json:"id" validate:"required"`
	SquadIDs       []int     `json:"squad_ids" validate:"required,min=1"`
	Username       string    `json:"username" validate:"omitempty"`
	Outbound       string    `json:"outbound" validate:"required"`
	Strategy       string    `json:"strategy" validate:"required,oneof=connection bypass"`
	ConnectionType string    `json:"connection_type" validate:"omitempty,oneof=default hwid mux ip"`
	LockType       string    `json:"lock_type" validate:"required,oneof=manager default"`
	Count          uint32    `json:"count" validate:"required"`
	CreatedAt      time.Time `json:"created_at" validate:"required"`
	UpdatedAt      time.Time `json:"updated_at" validate:"required"`
}

type ConnectionLimiterCreate struct {
	SquadIDs       []int  `json:"squad_ids" validate:"required,min=1"`
	Username       string `json:"username" validate:"omitempty"`
	Outbound       string `json:"outbound" validate:"required"`
	Strategy       string `json:"strategy" validate:"required,oneof=connection bypass"`
	ConnectionType string `json:"connection_type" validate:"excluded_if=Strategy bypass,omitempty,oneof=default hwid mux ip"`
	LockType       string `json:"lock_type" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass,omitempty,oneof=manager default"`
	Count          uint32 `json:"count" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type ConnectionLimiterUpdate struct {
	Username       string `json:"username" validate:"omitempty"`
	Outbound       string `json:"outbound" validate:"required"`
	Strategy       string `json:"strategy" validate:"required,oneof=connection bypass"`
	ConnectionType string `json:"connection_type" validate:"excluded_if=Strategy bypass,omitempty,oneof=default hwid mux ip"`
	LockType       string `json:"lock_type" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass,omitempty,oneof=manager default"`
	Count          uint32 `json:"count" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type BaseConnectionLimiter struct {
	Username       string `json:"username" validate:"omitempty"`
	Outbound       string `json:"outbound" validate:"required"`
	Strategy       string `json:"strategy" validate:"required,oneof=connection bypass"`
	ConnectionType string `json:"connection_type" validate:"excluded_if=Strategy bypass,omitempty,oneof=default hwid mux ip"`
	LockType       string `json:"lock_type" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass,omitempty,oneof=manager default"`
	Count          uint32 `json:"count" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type BandwidthLimiter struct {
	ID             int       `json:"id" validate:"required"`
	SquadIDs       []int     `json:"squad_ids" validate:"required,min=1"`
	Username       string    `json:"username" validate:"omitempty"`
	Outbound       string    `json:"outbound" validate:"required"`
	Strategy       string    `json:"strategy" validate:"required"`
	ConnectionType string    `json:"connection_type" validate:"omitempty"`
	Mode           string    `json:"mode" validate:"required"`
	FlowKeys       []string  `json:"flow_keys" validate:"omitempty,dive,oneof=user source_ip hwid mux protocol destination"`
	Speed          string    `json:"speed" validate:"required"`
	RawSpeed       uint64    `json:"raw_speed" validate:"required"`
	CreatedAt      time.Time `json:"created_at" validate:"required"`
	UpdatedAt      time.Time `json:"updated_at" validate:"required"`
}

type BandwidthLimiterCreate struct {
	SquadIDs       []int    `json:"squad_ids" validate:"required,min=1"`
	Username       string   `json:"username" validate:"omitempty"`
	Outbound       string   `json:"outbound" validate:"required"`
	Strategy       string   `json:"strategy" validate:"required,oneof=global connection bypass"`
	ConnectionType string   `json:"connection_type" validate:"excluded_if=Strategy bypass,omitempty"`
	Mode           string   `json:"mode" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	FlowKeys       []string `json:"flow_keys" validate:"excluded_if=Strategy bypass,omitempty,dive,oneof=user source_ip hwid mux protocol destination"`
	Speed          string   `json:"speed" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type BandwidthLimiterUpdate struct {
	Username       string   `json:"username" validate:"omitempty"`
	Outbound       string   `json:"outbound" validate:"required"`
	Strategy       string   `json:"strategy" validate:"required,oneof=global connection bypass"`
	ConnectionType string   `json:"connection_type" validate:"excluded_if=Strategy bypass,omitempty"`
	Mode           string   `json:"mode" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	FlowKeys       []string `json:"flow_keys" validate:"excluded_if=Strategy bypass,omitempty,dive,oneof=user source_ip hwid mux protocol destination"`
	Speed          string   `json:"speed" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type BaseBandwidthLimiter struct {
	Username       string   `json:"username" validate:"omitempty"`
	Outbound       string   `json:"outbound" validate:"required"`
	Strategy       string   `json:"strategy" validate:"required,oneof=global connection bypass"`
	ConnectionType string   `json:"connection_type" validate:"excluded_if=Strategy bypass,omitempty"`
	Mode           string   `json:"mode" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	FlowKeys       []string `json:"flow_keys" validate:"excluded_if=Strategy bypass,omitempty,dive,oneof=user source_ip hwid mux protocol destination"`
	Speed          string   `json:"speed" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	RawSpeed       uint64   `json:"raw_speed" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type TrafficLimiter struct {
	ID        int       `json:"id" validate:"required"`
	SquadIDs  []int     `json:"squad_ids" validate:"required,min=1"`
	Username  string    `json:"username" validate:"omitempty"`
	Outbound  string    `json:"outbound" validate:"required"`
	Strategy  string    `json:"strategy" validate:"required,oneof=global bypass"`
	Mode      string    `json:"mode" validate:"required"`
	RawUsed   uint64    `json:"raw_used" validate:"required"`
	Quota     string    `json:"quota" validate:"required"`
	RawQuota  uint64    `json:"raw_quota" validate:"required"`
	Usage     uint8     `json:"usage"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
	UpdatedAt time.Time `json:"updated_at" validate:"required"`
}

type TrafficLimiterCreate struct {
	SquadIDs []int  `json:"squad_ids" validate:"required,min=1"`
	Username string `json:"username" validate:"omitempty"`
	Outbound string `json:"outbound" validate:"required"`
	Strategy string `json:"strategy" validate:"required,oneof=global bypass"`
	Mode     string `json:"mode" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	Quota    string `json:"quota" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type TrafficLimiterUpdate struct {
	Username string `json:"username" validate:"omitempty"`
	Outbound string `json:"outbound" validate:"required"`
	Strategy string `json:"strategy" validate:"required,oneof=global bypass"`
	Mode     string `json:"mode" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	Quota    string `json:"quota" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type BaseTrafficLimiter struct {
	Username string `json:"username" validate:"omitempty"`
	Outbound string `json:"outbound" validate:"required"`
	Strategy string `json:"strategy" validate:"required,oneof=global bypass"`
	Mode     string `json:"mode" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	RawUsed  uint64 `json:"raw_used" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	Quota    string `json:"quota" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	RawQuota uint64 `json:"raw_quota" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type RateLimiter struct {
	ID             int       `json:"id" validate:"required"`
	SquadIDs       []int     `json:"squad_ids" validate:"required,min=1"`
	Username       string    `json:"username" validate:"omitempty"`
	Outbound       string    `json:"outbound" validate:"required"`
	Strategy       string    `json:"strategy" validate:"required,oneof=fixed_window sliding_window token_bucket leaky_bucket bypass"`
	ConnectionType string    `json:"connection_type" validate:"required,oneof=hwid mux ip default"`
	Count          uint32    `json:"count" validate:"required"`
	Interval       string    `json:"interval" validate:"required"`
	CreatedAt      time.Time `json:"created_at" validate:"required"`
	UpdatedAt      time.Time `json:"updated_at" validate:"required"`
}

type RateLimiterCreate struct {
	SquadIDs       []int  `json:"squad_ids" validate:"required,min=1"`
	Username       string `json:"username" validate:"omitempty"`
	Outbound       string `json:"outbound" validate:"required"`
	Strategy       string `json:"strategy" validate:"required,oneof=fixed_window sliding_window token_bucket leaky_bucket bypass"`
	ConnectionType string `json:"connection_type" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass,omitempty,oneof=hwid mux ip default"`
	Count          uint32 `json:"count" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	Interval       string `json:"interval" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type RateLimiterUpdate struct {
	Username       string `json:"username" validate:"omitempty"`
	Outbound       string `json:"outbound" validate:"required"`
	Strategy       string `json:"strategy" validate:"required,oneof=fixed_window sliding_window token_bucket leaky_bucket bypass"`
	ConnectionType string `json:"connection_type" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass,omitempty,oneof=hwid mux ip default"`
	Count          uint32 `json:"count" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	Interval       string `json:"interval" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}

type BaseRateLimiter struct {
	Username       string `json:"username" validate:"omitempty"`
	Outbound       string `json:"outbound" validate:"required"`
	Strategy       string `json:"strategy" validate:"required,oneof=fixed_window sliding_window token_bucket leaky_bucket bypass"`
	ConnectionType string `json:"connection_type" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass,omitempty,oneof=hwid mux ip default"`
	Count          uint32 `json:"count" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
	Interval       string `json:"interval" validate:"excluded_if=Strategy bypass,required_unless=Strategy bypass"`
}
