package server

import (
	"context"

	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/manager_api/grpc/manager"
)

func (s *Server) CreateSquad(_ context.Context, req *pb.SquadCreate) (*pb.Squad, error) {
	v, err := s.manager.CreateSquad(CM.SquadCreate{Name: req.GetName()})
	if err != nil {
		return nil, err
	}
	return convertSquad(v), nil
}

func (s *Server) GetSquads(_ context.Context, req *pb.Filters) (*pb.SquadList, error) {
	items, err := s.manager.GetSquads(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.Squad, len(items))
	for i, v := range items {
		out[i] = convertSquad(v)
	}
	return &pb.SquadList{Values: out}, nil
}

func (s *Server) GetSquadsCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetSquadsCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetSquad(_ context.Context, req *pb.IdRequest) (*pb.Squad, error) {
	v, err := s.manager.GetSquad(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertSquad(v), nil
}

func (s *Server) UpdateSquad(_ context.Context, req *pb.SquadUpdateRequest) (*pb.Squad, error) {
	v, err := s.manager.UpdateSquad(int(req.GetId()), CM.SquadUpdate{Name: req.GetUpdate().GetName()})
	if err != nil {
		return nil, err
	}
	return convertSquad(v), nil
}

func (s *Server) DeleteSquad(_ context.Context, req *pb.IdRequest) (*pb.Squad, error) {
	v, err := s.manager.DeleteSquad(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertSquad(v), nil
}

func (s *Server) CreateNode(_ context.Context, req *pb.NodeCreate) (*pb.Node, error) {
	v, err := s.manager.CreateNode(CM.NodeCreate{
		UUID:     req.GetUuid(),
		Name:     req.GetName(),
		SquadIDs: toIntSlice(req.GetSquadIds()),
	})
	if err != nil {
		return nil, err
	}
	return convertNode(v), nil
}

func (s *Server) GetNodes(_ context.Context, req *pb.Filters) (*pb.NodeList, error) {
	items, err := s.manager.GetNodes(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.Node, len(items))
	for i, v := range items {
		out[i] = convertNode(v)
	}
	return &pb.NodeList{Values: out}, nil
}

func (s *Server) GetNodesCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetNodesCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetNode(_ context.Context, req *pb.UuidRequest) (*pb.Node, error) {
	v, err := s.manager.GetNode(req.GetUuid())
	if err != nil {
		return nil, err
	}
	return convertNode(v), nil
}

func (s *Server) GetNodeStatus(_ context.Context, req *pb.UuidRequest) (*pb.NodeStatusReply, error) {
	status, err := s.manager.GetNodeStatus(req.GetUuid())
	if err != nil {
		return nil, err
	}
	return &pb.NodeStatusReply{Status: status}, nil
}

func (s *Server) UpdateNode(_ context.Context, req *pb.NodeUpdateRequest) (*pb.Node, error) {
	v, err := s.manager.UpdateNode(req.GetUuid(), CM.NodeUpdate{Name: req.GetUpdate().GetName()})
	if err != nil {
		return nil, err
	}
	return convertNode(v), nil
}

func (s *Server) DeleteNode(_ context.Context, req *pb.UuidRequest) (*pb.Node, error) {
	v, err := s.manager.DeleteNode(req.GetUuid())
	if err != nil {
		return nil, err
	}
	return convertNode(v), nil
}

func (s *Server) CreateUser(_ context.Context, req *pb.UserCreate) (*pb.User, error) {
	v, err := s.manager.CreateUser(CM.UserCreate{
		SquadIDs:       toIntSlice(req.GetSquadIds()),
		Username:       req.GetUsername(),
		Inbound:        req.GetInbound(),
		Type:           req.GetType(),
		UUID:           req.GetUuid(),
		Password:       req.GetPassword(),
		Secret:         req.GetSecret(),
		AuthorizedKeys: req.GetAuthorizedKeys(),
		Flow:           req.GetFlow(),
		AlterID:        int(req.GetAlterId()),
	})
	if err != nil {
		return nil, err
	}
	return convertUser(v), nil
}

func (s *Server) GetUsers(_ context.Context, req *pb.Filters) (*pb.UserList, error) {
	items, err := s.manager.GetUsers(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.User, len(items))
	for i, v := range items {
		out[i] = convertUser(v)
	}
	return &pb.UserList{Values: out}, nil
}

func (s *Server) GetUsersCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetUsersCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetUser(_ context.Context, req *pb.IdRequest) (*pb.User, error) {
	v, err := s.manager.GetUser(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertUser(v), nil
}

func (s *Server) UpdateUser(_ context.Context, req *pb.UserUpdateRequest) (*pb.User, error) {
	u := req.GetUpdate()
	v, err := s.manager.UpdateUser(int(req.GetId()), CM.UserUpdate{
		UUID:           u.GetUuid(),
		Password:       u.GetPassword(),
		Secret:         u.GetSecret(),
		AuthorizedKeys: u.GetAuthorizedKeys(),
		Flow:           u.GetFlow(),
		AlterID:        int(u.GetAlterId()),
	})
	if err != nil {
		return nil, err
	}
	return convertUser(v), nil
}

func (s *Server) DeleteUser(_ context.Context, req *pb.IdRequest) (*pb.User, error) {
	v, err := s.manager.DeleteUser(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertUser(v), nil
}

func (s *Server) CreateBandwidthLimiter(_ context.Context, req *pb.BandwidthLimiterCreate) (*pb.BandwidthLimiter, error) {
	v, err := s.manager.CreateBandwidthLimiter(CM.BandwidthLimiterCreate{
		SquadIDs:       toIntSlice(req.GetSquadIds()),
		Username:       req.GetUsername(),
		Outbound:       req.GetOutbound(),
		Strategy:       req.GetStrategy(),
		ConnectionType: req.GetConnectionType(),
		Mode:           req.GetMode(),
		FlowKeys:       req.GetFlowKeys(),
		Speed:          req.GetSpeed(),
	})
	if err != nil {
		return nil, err
	}
	return convertBandwidthLimiter(v), nil
}

func (s *Server) GetBandwidthLimiters(_ context.Context, req *pb.Filters) (*pb.BandwidthLimiterList, error) {
	items, err := s.manager.GetBandwidthLimiters(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.BandwidthLimiter, len(items))
	for i, v := range items {
		out[i] = convertBandwidthLimiter(v)
	}
	return &pb.BandwidthLimiterList{Values: out}, nil
}

func (s *Server) GetBandwidthLimitersCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetBandwidthLimitersCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetBandwidthLimiter(_ context.Context, req *pb.IdRequest) (*pb.BandwidthLimiter, error) {
	v, err := s.manager.GetBandwidthLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertBandwidthLimiter(v), nil
}

func (s *Server) UpdateBandwidthLimiter(_ context.Context, req *pb.BandwidthLimiterUpdateRequest) (*pb.BandwidthLimiter, error) {
	u := req.GetUpdate()
	v, err := s.manager.UpdateBandwidthLimiter(int(req.GetId()), CM.BandwidthLimiterUpdate{
		Username:       u.GetUsername(),
		Outbound:       u.GetOutbound(),
		Strategy:       u.GetStrategy(),
		ConnectionType: u.GetConnectionType(),
		Mode:           u.GetMode(),
		FlowKeys:       u.GetFlowKeys(),
		Speed:          u.GetSpeed(),
	})
	if err != nil {
		return nil, err
	}
	return convertBandwidthLimiter(v), nil
}

func (s *Server) DeleteBandwidthLimiter(_ context.Context, req *pb.IdRequest) (*pb.BandwidthLimiter, error) {
	v, err := s.manager.DeleteBandwidthLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertBandwidthLimiter(v), nil
}

func (s *Server) CreateTrafficLimiter(_ context.Context, req *pb.TrafficLimiterCreate) (*pb.TrafficLimiter, error) {
	v, err := s.manager.CreateTrafficLimiter(CM.TrafficLimiterCreate{
		SquadIDs: toIntSlice(req.GetSquadIds()),
		Username: req.GetUsername(),
		Outbound: req.GetOutbound(),
		Strategy: req.GetStrategy(),
		Mode:     req.GetMode(),
		Quota:    req.GetQuota(),
	})
	if err != nil {
		return nil, err
	}
	return convertTrafficLimiter(v), nil
}

func (s *Server) GetTrafficLimiters(_ context.Context, req *pb.Filters) (*pb.TrafficLimiterList, error) {
	items, err := s.manager.GetTrafficLimiters(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.TrafficLimiter, len(items))
	for i, v := range items {
		out[i] = convertTrafficLimiter(v)
	}
	return &pb.TrafficLimiterList{Values: out}, nil
}

func (s *Server) GetTrafficLimitersCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetTrafficLimitersCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetTrafficLimiter(_ context.Context, req *pb.IdRequest) (*pb.TrafficLimiter, error) {
	v, err := s.manager.GetTrafficLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertTrafficLimiter(v), nil
}

func (s *Server) UpdateTrafficLimiter(_ context.Context, req *pb.TrafficLimiterUpdateRequest) (*pb.TrafficLimiter, error) {
	u := req.GetUpdate()
	v, err := s.manager.UpdateTrafficLimiter(int(req.GetId()), CM.TrafficLimiterUpdate{
		Username: u.GetUsername(),
		Outbound: u.GetOutbound(),
		Strategy: u.GetStrategy(),
		Mode:     u.GetMode(),
		Quota:    u.GetQuota(),
	})
	if err != nil {
		return nil, err
	}
	return convertTrafficLimiter(v), nil
}

func (s *Server) DeleteTrafficLimiter(_ context.Context, req *pb.IdRequest) (*pb.TrafficLimiter, error) {
	v, err := s.manager.DeleteTrafficLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertTrafficLimiter(v), nil
}

func (s *Server) CreateConnectionLimiter(_ context.Context, req *pb.ConnectionLimiterCreate) (*pb.ConnectionLimiter, error) {
	v, err := s.manager.CreateConnectionLimiter(CM.ConnectionLimiterCreate{
		SquadIDs:       toIntSlice(req.GetSquadIds()),
		Username:       req.GetUsername(),
		Outbound:       req.GetOutbound(),
		Strategy:       req.GetStrategy(),
		ConnectionType: req.GetConnectionType(),
		LockType:       req.GetLockType(),
		Count:          req.GetCount(),
	})
	if err != nil {
		return nil, err
	}
	return convertConnectionLimiter(v), nil
}

func (s *Server) GetConnectionLimiters(_ context.Context, req *pb.Filters) (*pb.ConnectionLimiterList, error) {
	items, err := s.manager.GetConnectionLimiters(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.ConnectionLimiter, len(items))
	for i, v := range items {
		out[i] = convertConnectionLimiter(v)
	}
	return &pb.ConnectionLimiterList{Values: out}, nil
}

func (s *Server) GetConnectionLimitersCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetConnectionLimitersCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetConnectionLimiter(_ context.Context, req *pb.IdRequest) (*pb.ConnectionLimiter, error) {
	v, err := s.manager.GetConnectionLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertConnectionLimiter(v), nil
}

func (s *Server) UpdateConnectionLimiter(_ context.Context, req *pb.ConnectionLimiterUpdateRequest) (*pb.ConnectionLimiter, error) {
	u := req.GetUpdate()
	v, err := s.manager.UpdateConnectionLimiter(int(req.GetId()), CM.ConnectionLimiterUpdate{
		Username:       u.GetUsername(),
		Outbound:       u.GetOutbound(),
		Strategy:       u.GetStrategy(),
		ConnectionType: u.GetConnectionType(),
		LockType:       u.GetLockType(),
		Count:          u.GetCount(),
	})
	if err != nil {
		return nil, err
	}
	return convertConnectionLimiter(v), nil
}

func (s *Server) DeleteConnectionLimiter(_ context.Context, req *pb.IdRequest) (*pb.ConnectionLimiter, error) {
	v, err := s.manager.DeleteConnectionLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertConnectionLimiter(v), nil
}

func (s *Server) CreateRateLimiter(_ context.Context, req *pb.RateLimiterCreate) (*pb.RateLimiter, error) {
	v, err := s.manager.CreateRateLimiter(CM.RateLimiterCreate{
		SquadIDs:       toIntSlice(req.GetSquadIds()),
		Username:       req.GetUsername(),
		Outbound:       req.GetOutbound(),
		Strategy:       req.GetStrategy(),
		ConnectionType: req.GetConnectionType(),
		Count:          req.GetCount(),
		Interval:       req.GetInterval(),
	})
	if err != nil {
		return nil, err
	}
	return convertRateLimiter(v), nil
}

func (s *Server) GetRateLimiters(_ context.Context, req *pb.Filters) (*pb.RateLimiterList, error) {
	items, err := s.manager.GetRateLimiters(convertListFilters(req))
	if err != nil {
		return nil, err
	}
	out := make([]*pb.RateLimiter, len(items))
	for i, v := range items {
		out[i] = convertRateLimiter(v)
	}
	return &pb.RateLimiterList{Values: out}, nil
}

func (s *Server) GetRateLimitersCount(_ context.Context, req *pb.Filters) (*pb.CountReply, error) {
	n, err := s.manager.GetRateLimitersCount(convertFilters(req))
	if err != nil {
		return nil, err
	}
	return &pb.CountReply{Count: int64(n)}, nil
}

func (s *Server) GetRateLimiter(_ context.Context, req *pb.IdRequest) (*pb.RateLimiter, error) {
	v, err := s.manager.GetRateLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertRateLimiter(v), nil
}

func (s *Server) UpdateRateLimiter(_ context.Context, req *pb.RateLimiterUpdateRequest) (*pb.RateLimiter, error) {
	u := req.GetUpdate()
	v, err := s.manager.UpdateRateLimiter(int(req.GetId()), CM.RateLimiterUpdate{
		Username:       u.GetUsername(),
		Outbound:       u.GetOutbound(),
		Strategy:       u.GetStrategy(),
		ConnectionType: u.GetConnectionType(),
		Count:          u.GetCount(),
		Interval:       u.GetInterval(),
	})
	if err != nil {
		return nil, err
	}
	return convertRateLimiter(v), nil
}

func (s *Server) DeleteRateLimiter(_ context.Context, req *pb.IdRequest) (*pb.RateLimiter, error) {
	v, err := s.manager.DeleteRateLimiter(int(req.GetId()))
	if err != nil {
		return nil, err
	}
	return convertRateLimiter(v), nil
}
