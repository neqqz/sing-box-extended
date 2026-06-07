package server

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/log"
	CS "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/node_manager_api/manager"
	E "github.com/sagernet/sing/common/exceptions"
	"google.golang.org/grpc"
)

type RemoteNode struct {
	ctx    context.Context
	logger log.ContextLogger
	stream grpc.ServerStreamingServer[pb.NodeData]

	err     error
	errChan chan error

	mtx sync.Mutex
}

func NewRemoteNode(ctx context.Context, logger log.ContextLogger, stream grpc.ServerStreamingServer[pb.NodeData]) (*RemoteNode, chan error) {
	errChan := make(chan error)
	return &RemoteNode{
		ctx:     ctx,
		logger:  logger,
		stream:  stream,
		errChan: errChan,
	}, errChan
}

func (s *RemoteNode) UpdateUser(user CS.User) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateUser,
		Data: &pb.NodeData_User{User: s.convertUser(user)},
	})
}

func (s *RemoteNode) UpdateUsers(users []CS.User) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	pbUsers := make([]*pb.User, len(users))
	for i, user := range users {
		pbUsers[i] = s.convertUser(user)
	}
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateUsers,
		Data: &pb.NodeData_Users{Users: &pb.UserList{Values: pbUsers}},
	})
}

func (s *RemoteNode) DeleteUser(user CS.User) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_deleteUser,
		Data: &pb.NodeData_User{User: s.convertUser(user)},
	})
}

func (s *RemoteNode) UpdateConnectionLimiter(limiter CS.ConnectionLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateConnectionLimiter,
		Data: &pb.NodeData_ConnectionLimiter{ConnectionLimiter: s.convertConnectionLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateConnectionLimiters(limiters []CS.ConnectionLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	pbLimiters := make([]*pb.ConnectionLimiter, len(limiters))
	for i, limiters := range limiters {
		pbLimiters[i] = s.convertConnectionLimiter(limiters)
	}
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateConnectionLimiters,
		Data: &pb.NodeData_ConnectionLimiters{ConnectionLimiters: &pb.ConnectionLimiterList{Values: pbLimiters}},
	})
}

func (s *RemoteNode) DeleteConnectionLimiter(limiter CS.ConnectionLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_deleteConnectionLimiter,
		Data: &pb.NodeData_ConnectionLimiter{ConnectionLimiter: s.convertConnectionLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateBandwidthLimiter(limiter CS.BandwidthLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateBandwidthLimiter,
		Data: &pb.NodeData_BandwidthLimiter{BandwidthLimiter: s.convertBandwidthLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateBandwidthLimiters(limiters []CS.BandwidthLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	pbLimiters := make([]*pb.BandwidthLimiter, len(limiters))
	for i, limiters := range limiters {
		pbLimiters[i] = s.convertBandwidthLimiter(limiters)
	}
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateBandwidthLimiters,
		Data: &pb.NodeData_BandwidthLimiters{BandwidthLimiters: &pb.BandwidthLimiterList{Values: pbLimiters}},
	})
}

func (s *RemoteNode) DeleteBandwidthLimiter(limiter CS.BandwidthLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_deleteBandwidthLimiter,
		Data: &pb.NodeData_BandwidthLimiter{BandwidthLimiter: s.convertBandwidthLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateTrafficLimiter(limiter CS.TrafficLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateTrafficLimiter,
		Data: &pb.NodeData_TrafficLimiter{TrafficLimiter: s.convertTrafficLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateTrafficLimiters(limiters []CS.TrafficLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	pbLimiters := make([]*pb.TrafficLimiter, len(limiters))
	for i, limiters := range limiters {
		pbLimiters[i] = s.convertTrafficLimiter(limiters)
	}
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateTrafficLimiters,
		Data: &pb.NodeData_TrafficLimiters{TrafficLimiters: &pb.TrafficLimiterList{Values: pbLimiters}},
	})
}

func (s *RemoteNode) DeleteTrafficLimiter(limiter CS.TrafficLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_deleteTrafficLimiter,
		Data: &pb.NodeData_TrafficLimiter{TrafficLimiter: s.convertTrafficLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateRateLimiter(limiter CS.RateLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateRateLimiter,
		Data: &pb.NodeData_RateLimiter{RateLimiter: s.convertRateLimiter(limiter)},
	})
}

func (s *RemoteNode) UpdateRateLimiters(limiters []CS.RateLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	pbLimiters := make([]*pb.RateLimiter, len(limiters))
	for i, limiters := range limiters {
		pbLimiters[i] = s.convertRateLimiter(limiters)
	}
	s.send(&pb.NodeData{
		Op:   pb.OpType_updateRateLimiters,
		Data: &pb.NodeData_RateLimiters{RateLimiters: &pb.RateLimiterList{Values: pbLimiters}},
	})
}

func (s *RemoteNode) DeleteRateLimiter(limiter CS.RateLimiter) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.send(&pb.NodeData{
		Op:   pb.OpType_deleteRateLimiter,
		Data: &pb.NodeData_RateLimiter{RateLimiter: s.convertRateLimiter(limiter)},
	})
}

func (s *RemoteNode) IsLocal() bool {
	return false
}

func (s *RemoteNode) IsOnline() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	select {
	case <-s.stream.Context().Done():
		return false
	default:
		return true
	}
}

func (s *RemoteNode) Close() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.close(E.New("server connection is closed"))
	return nil
}

func (s *RemoteNode) send(data *pb.NodeData) {
	if s.err != nil {
		return
	}
	select {
	case <-s.ctx.Done():
		s.close(E.New("server connection is closed"))
		return
	case <-s.stream.Context().Done():
		s.close(E.New("client connection is closed"))
		return
	default:
	}
	err := s.stream.Send(data)
	if err != nil {
		s.close(err)
	}
}

func (s *RemoteNode) close(err error) {
	if err == nil || s.err != nil {
		return
	}
	s.err = err
	s.errChan <- err
	close(s.errChan)
}

func (s *RemoteNode) convertUser(user CS.User) *pb.User {
	return &pb.User{
		Id:             int32(user.ID),
		Username:       user.Username,
		Inbound:        user.Inbound,
		Type:           user.Type,
		Uuid:           user.UUID,
		Password:       user.Password,
		Secret:         user.Secret,
		AuthorizedKeys: user.AuthorizedKeys,
		Flow:           user.Flow,
		AlterId:        int32(user.AlterID),
	}
}

func (s *RemoteNode) convertConnectionLimiter(limiter CS.ConnectionLimiter) *pb.ConnectionLimiter {
	return &pb.ConnectionLimiter{
		Id:             int32(limiter.ID),
		Username:       limiter.Username,
		Outbound:       limiter.Outbound,
		Strategy:       limiter.Strategy,
		ConnectionType: limiter.ConnectionType,
		LockType:       limiter.LockType,
		Count:          limiter.Count,
	}
}

func (s *RemoteNode) convertBandwidthLimiter(limiter CS.BandwidthLimiter) *pb.BandwidthLimiter {
	return &pb.BandwidthLimiter{
		Id:             int32(limiter.ID),
		Username:       limiter.Username,
		Outbound:       limiter.Outbound,
		Strategy:       limiter.Strategy,
		ConnectionType: limiter.ConnectionType,
		Mode:           limiter.Mode,
		FlowKeys:       limiter.FlowKeys,
		Speed:          limiter.Speed,
		RawSpeed:       limiter.RawSpeed,
	}
}

func (s *RemoteNode) convertTrafficLimiter(limiter CS.TrafficLimiter) *pb.TrafficLimiter {
	return &pb.TrafficLimiter{
		Id:       int32(limiter.ID),
		Username: limiter.Username,
		Outbound: limiter.Outbound,
		Strategy: limiter.Strategy,
		Mode:     limiter.Mode,
		RawUsed:  limiter.RawUsed,
		Quota:    limiter.Quota,
		RawQuota: limiter.RawQuota,
	}
}

func (s *RemoteNode) convertRateLimiter(limiter CS.RateLimiter) *pb.RateLimiter {
	return &pb.RateLimiter{
		Id:             int32(limiter.ID),
		Username:       limiter.Username,
		Outbound:       limiter.Outbound,
		Strategy:       limiter.Strategy,
		ConnectionType: limiter.ConnectionType,
		Count:          limiter.Count,
		Interval:       limiter.Interval,
	}
}
