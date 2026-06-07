package client

import (
	"time"

	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/manager_api/grpc/manager"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return CM.ErrNotFound
	}
	return err
}

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

func timeFromNano(ns int64) time.Time { return time.Unix(0, ns) }

func convertSquad(v *pb.Squad) CM.Squad {
	return CM.Squad{
		ID:        int(v.GetId()),
		Name:      v.GetName(),
		CreatedAt: timeFromNano(v.GetCreatedAt()),
		UpdatedAt: timeFromNano(v.GetUpdatedAt()),
	}
}

func convertNode(v *pb.Node) CM.Node {
	return CM.Node{
		UUID:      v.GetUuid(),
		Name:      v.GetName(),
		SquadIDs:  toIntSlice(v.GetSquadIds()),
		CreatedAt: timeFromNano(v.GetCreatedAt()),
		UpdatedAt: timeFromNano(v.GetUpdatedAt()),
	}
}

func convertUser(v *pb.User) CM.User {
	return CM.User{
		ID:             int(v.GetId()),
		SquadIDs:       toIntSlice(v.GetSquadIds()),
		Username:       v.GetUsername(),
		Inbound:        v.GetInbound(),
		Type:           v.GetType(),
		UUID:           v.GetUuid(),
		Password:       v.GetPassword(),
		Secret:         v.GetSecret(),
		AuthorizedKeys: v.GetAuthorizedKeys(),
		Flow:           v.GetFlow(),
		AlterID:        int(v.GetAlterId()),
		CreatedAt:      timeFromNano(v.GetCreatedAt()),
		UpdatedAt:      timeFromNano(v.GetUpdatedAt()),
	}
}

func convertBandwidthLimiter(v *pb.BandwidthLimiter) CM.BandwidthLimiter {
	return CM.BandwidthLimiter{
		ID:             int(v.GetId()),
		SquadIDs:       toIntSlice(v.GetSquadIds()),
		Username:       v.GetUsername(),
		Outbound:       v.GetOutbound(),
		Strategy:       v.GetStrategy(),
		ConnectionType: v.GetConnectionType(),
		Mode:           v.GetMode(),
		FlowKeys:       v.GetFlowKeys(),
		Speed:          v.GetSpeed(),
		RawSpeed:       v.GetRawSpeed(),
		CreatedAt:      timeFromNano(v.GetCreatedAt()),
		UpdatedAt:      timeFromNano(v.GetUpdatedAt()),
	}
}

func convertTrafficLimiter(v *pb.TrafficLimiter) CM.TrafficLimiter {
	return CM.TrafficLimiter{
		ID:        int(v.GetId()),
		SquadIDs:  toIntSlice(v.GetSquadIds()),
		Username:  v.GetUsername(),
		Outbound:  v.GetOutbound(),
		Strategy:  v.GetStrategy(),
		Mode:      v.GetMode(),
		RawUsed:   v.GetRawUsed(),
		Quota:     v.GetQuota(),
		RawQuota:  v.GetRawQuota(),
		CreatedAt: timeFromNano(v.GetCreatedAt()),
		UpdatedAt: timeFromNano(v.GetUpdatedAt()),
	}
}

func convertConnectionLimiter(v *pb.ConnectionLimiter) CM.ConnectionLimiter {
	return CM.ConnectionLimiter{
		ID:             int(v.GetId()),
		SquadIDs:       toIntSlice(v.GetSquadIds()),
		Username:       v.GetUsername(),
		Outbound:       v.GetOutbound(),
		Strategy:       v.GetStrategy(),
		ConnectionType: v.GetConnectionType(),
		LockType:       v.GetLockType(),
		Count:          v.GetCount(),
		CreatedAt:      timeFromNano(v.GetCreatedAt()),
		UpdatedAt:      timeFromNano(v.GetUpdatedAt()),
	}
}

func convertRateLimiter(v *pb.RateLimiter) CM.RateLimiter {
	return CM.RateLimiter{
		ID:             int(v.GetId()),
		SquadIDs:       toIntSlice(v.GetSquadIds()),
		Username:       v.GetUsername(),
		Outbound:       v.GetOutbound(),
		Strategy:       v.GetStrategy(),
		ConnectionType: v.GetConnectionType(),
		Count:          v.GetCount(),
		Interval:       v.GetInterval(),
		CreatedAt:      timeFromNano(v.GetCreatedAt()),
		UpdatedAt:      timeFromNano(v.GetUpdatedAt()),
	}
}

func convertFilters(filters map[string][]string) *pb.Filters {
	values := make(map[string]*pb.StringList, len(filters))
	for k, v := range filters {
		values[k] = &pb.StringList{Values: append([]string(nil), v...)}
	}
	return &pb.Filters{Values: values}
}
