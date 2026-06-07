package server

import (
	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/manager_api/grpc/manager"
)

func toIntSlice(values []int32) []int {
	out := make([]int, len(values))
	for i, v := range values {
		out[i] = int(v)
	}
	return out
}

func toInt32Slice(values []int) []int32 {
	out := make([]int32, len(values))
	for i, v := range values {
		out[i] = int32(v)
	}
	return out
}

func convertSquad(v CM.Squad) *pb.Squad {
	return &pb.Squad{
		Id:        int32(v.ID),
		Name:      v.Name,
		CreatedAt: v.CreatedAt.UnixNano(),
		UpdatedAt: v.UpdatedAt.UnixNano(),
	}
}

func convertNode(v CM.Node) *pb.Node {
	return &pb.Node{
		Uuid:      v.UUID,
		Name:      v.Name,
		SquadIds:  toInt32Slice(v.SquadIDs),
		CreatedAt: v.CreatedAt.UnixNano(),
		UpdatedAt: v.UpdatedAt.UnixNano(),
	}
}

func convertUser(v CM.User) *pb.User {
	return &pb.User{
		Id:             int32(v.ID),
		SquadIds:       toInt32Slice(v.SquadIDs),
		Username:       v.Username,
		Inbound:        v.Inbound,
		Type:           v.Type,
		Uuid:           v.UUID,
		Password:       v.Password,
		Secret:         v.Secret,
		AuthorizedKeys: v.AuthorizedKeys,
		Flow:           v.Flow,
		AlterId:        int32(v.AlterID),
		CreatedAt:      v.CreatedAt.UnixNano(),
		UpdatedAt:      v.UpdatedAt.UnixNano(),
	}
}

func convertBandwidthLimiter(v CM.BandwidthLimiter) *pb.BandwidthLimiter {
	return &pb.BandwidthLimiter{
		Id:             int32(v.ID),
		SquadIds:       toInt32Slice(v.SquadIDs),
		Username:       v.Username,
		Outbound:       v.Outbound,
		Strategy:       v.Strategy,
		ConnectionType: v.ConnectionType,
		Mode:           v.Mode,
		FlowKeys:       v.FlowKeys,
		Speed:          v.Speed,
		RawSpeed:       v.RawSpeed,
		CreatedAt:      v.CreatedAt.UnixNano(),
		UpdatedAt:      v.UpdatedAt.UnixNano(),
	}
}

func convertTrafficLimiter(v CM.TrafficLimiter) *pb.TrafficLimiter {
	return &pb.TrafficLimiter{
		Id:        int32(v.ID),
		SquadIds:  toInt32Slice(v.SquadIDs),
		Username:  v.Username,
		Outbound:  v.Outbound,
		Strategy:  v.Strategy,
		Mode:      v.Mode,
		RawUsed:   v.RawUsed,
		Quota:     v.Quota,
		RawQuota:  v.RawQuota,
		CreatedAt: v.CreatedAt.UnixNano(),
		UpdatedAt: v.UpdatedAt.UnixNano(),
	}
}

func convertConnectionLimiter(v CM.ConnectionLimiter) *pb.ConnectionLimiter {
	return &pb.ConnectionLimiter{
		Id:             int32(v.ID),
		SquadIds:       toInt32Slice(v.SquadIDs),
		Username:       v.Username,
		Outbound:       v.Outbound,
		Strategy:       v.Strategy,
		ConnectionType: v.ConnectionType,
		LockType:       v.LockType,
		Count:          v.Count,
		CreatedAt:      v.CreatedAt.UnixNano(),
		UpdatedAt:      v.UpdatedAt.UnixNano(),
	}
}

func convertRateLimiter(v CM.RateLimiter) *pb.RateLimiter {
	return &pb.RateLimiter{
		Id:             int32(v.ID),
		SquadIds:       toInt32Slice(v.SquadIDs),
		Username:       v.Username,
		Outbound:       v.Outbound,
		Strategy:       v.Strategy,
		ConnectionType: v.ConnectionType,
		Count:          v.Count,
		Interval:       v.Interval,
		CreatedAt:      v.CreatedAt.UnixNano(),
		UpdatedAt:      v.UpdatedAt.UnixNano(),
	}
}

func convertFilters(req *pb.Filters) map[string][]string {
	filters := map[string][]string{}
	for k, v := range req.GetValues() {
		filters[k] = append([]string(nil), v.GetValues()...)
	}
	return filters
}

func convertListFilters(req *pb.Filters) map[string][]string {
	filters := convertFilters(req)
	if _, ok := filters["limit"]; !ok {
		filters["limit"] = []string{"100"}
	}
	return filters
}
