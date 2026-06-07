// Mirrors the DTOs declared in service/manager/constant/dto.go.
// Strings stay strings (the server emits time.Time as RFC3339).

export type SquadIDs = number[];

export interface Squad {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
}
export interface SquadCreate {
  name: string;
}
export interface SquadUpdate {
  name: string;
}

export interface Node {
  uuid: string;
  name: string;
  squad_ids: SquadIDs;
  created_at: string;
  updated_at: string;
}
export interface NodeCreate {
  uuid: string;
  name: string;
  squad_ids: SquadIDs;
}
export interface NodeUpdate {
  name: string;
}
export type NodeStatus = "online" | "offline";

export type UserType =
  | "anytls"
  | "http"
  | "hysteria"
  | "hysteria2"
  | "mixed"
  | "mtproxy"
  | "naive"
  | "socks"
  | "ssh"
  | "trojan"
  | "trusttunnel"
  | "tuic"
  | "vless"
  | "vmess";

export interface User {
  id: number;
  squad_ids: SquadIDs;
  username: string;
  inbound: string;
  type: UserType;
  uuid: string;
  password: string;
  secret: string;
  authorized_keys: string[];
  flow: string;
  alter_id: number;
  created_at: string;
  updated_at: string;
}
export interface UserCreate {
  squad_ids: SquadIDs;
  username: string;
  inbound: string;
  type: UserType;
  uuid?: string;
  password?: string;
  secret?: string;
  authorized_keys?: string[];
  flow?: string;
  alter_id?: number;
}
export interface UserUpdate {
  uuid?: string;
  password?: string;
  secret?: string;
  authorized_keys?: string[];
  flow?: string;
  alter_id?: number;
}

export type BandwidthStrategy = "global" | "connection" | "bypass";
export type BandwidthMode = "upload" | "download" | "bidirectional";
export type ConnectionType = "default" | "hwid" | "mux" | "source_ip";

export interface BandwidthLimiter {
  id: number;
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: BandwidthStrategy;
  connection_type?: ConnectionType;
  mode: BandwidthMode;
  flow_keys?: string[];
  speed: string;
  raw_speed: number;
  created_at: string;
  updated_at: string;
}
// `mode`, `flow_keys`, `connection_type` and `speed` carry
// `excluded_if=Strategy bypass` on the manager-api DTO (see
// service/manager/constant/dto.go) — they must be omitted from the
// JSON body when strategy="bypass", otherwise the SQL repository
// fails to parse `speed=""` via byteformats.NetworkBytesCompat and
// the request is rejected with 400 "invalid format". Marking them
// optional here lets the page builders drop them via
// `JSON.stringify`'s `undefined`-skips-key behaviour.
export interface BandwidthLimiterCreate {
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: BandwidthStrategy;
  connection_type?: ConnectionType;
  mode?: BandwidthMode;
  flow_keys?: string[];
  speed?: string;
}
export interface BandwidthLimiterUpdate {
  username?: string;
  outbound: string;
  strategy: BandwidthStrategy;
  connection_type?: ConnectionType;
  mode?: BandwidthMode;
  flow_keys?: string[];
  speed?: string;
}

export type TrafficStrategy = "global" | "bypass";
export type TrafficMode = BandwidthMode;
export interface TrafficLimiter {
  id: number;
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: TrafficStrategy;
  mode: TrafficMode;
  raw_used: number;
  quota: string;
  raw_quota: number;
  usage: number;
  created_at: string;
  updated_at: string;
}
// `mode` / `quota` are excluded_if=Strategy bypass on the DTO; see the
// BandwidthLimiterCreate comment above for the full rationale.
export interface TrafficLimiterCreate {
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: TrafficStrategy;
  mode?: TrafficMode;
  quota?: string;
}
export interface TrafficLimiterUpdate {
  username?: string;
  outbound: string;
  strategy: TrafficStrategy;
  mode?: TrafficMode;
  quota?: string;
}

export type ConnectionStrategy = "connection" | "bypass";
export type LockType = "manager" | "default";

export interface ConnectionLimiter {
  id: number;
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: ConnectionStrategy;
  connection_type?: ConnectionType;
  lock_type: LockType;
  count: number;
  created_at: string;
  updated_at: string;
}
// `connection_type` / `lock_type` / `count` are excluded_if=Strategy
// bypass on the DTO; see the BandwidthLimiterCreate comment above for
// the full rationale.
export interface ConnectionLimiterCreate {
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: ConnectionStrategy;
  connection_type?: ConnectionType;
  lock_type?: LockType;
  count?: number;
}
export interface ConnectionLimiterUpdate {
  username?: string;
  outbound: string;
  strategy: ConnectionStrategy;
  connection_type?: ConnectionType;
  lock_type?: LockType;
  count?: number;
}

export type RateStrategy =
  | "fixed_window"
  | "sliding_window"
  | "token_bucket"
  | "leaky_bucket"
  | "bypass";
export type RateConnectionType = "hwid" | "mux" | "source_ip" | "default";

export interface RateLimiter {
  id: number;
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: RateStrategy;
  connection_type: RateConnectionType;
  count: number;
  interval: string;
  created_at: string;
  updated_at: string;
}
// `connection_type` / `count` / `interval` are excluded_if=Strategy
// bypass on the DTO; see the BandwidthLimiterCreate comment above for
// the full rationale.
export interface RateLimiterCreate {
  squad_ids: SquadIDs;
  username?: string;
  outbound: string;
  strategy: RateStrategy;
  connection_type?: RateConnectionType;
  count?: number;
  interval?: string;
}
export interface RateLimiterUpdate {
  username?: string;
  outbound: string;
  strategy: RateStrategy;
  connection_type?: RateConnectionType;
  count?: number;
  interval?: string;
}

export interface CountResponse {
  count: number;
}
// Mirrors the JSON shape returned by `GET /manager/v1/version` —
// see service/manager_api/http/server/server.go.
export interface VersionInfo {
  version: string;
  website: string;
}

export type Listable = Record<string, string | number | boolean | string[] | number[] | undefined | null>;
