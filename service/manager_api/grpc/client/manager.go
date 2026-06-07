package client

import (
	CM "github.com/sagernet/sing-box/service/manager/constant"
	pb "github.com/sagernet/sing-box/service/manager_api/grpc/manager"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ CM.Manager = (*Client)(nil)

func (s *Client) CreateSquad(in CM.SquadCreate) (CM.Squad, error) {
	c, err := s.client()
	if err != nil {
		return CM.Squad{}, err
	}
	reply, err := c.CreateSquad(s.callContext(), &pb.SquadCreate{Name: in.Name})
	if err != nil {
		return CM.Squad{}, mapError(err)
	}
	return convertSquad(reply), nil
}

func (s *Client) GetSquads(filters map[string][]string) ([]CM.Squad, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetSquads(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.Squad, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertSquad(v)
	}
	return out, nil
}

func (s *Client) GetSquadsCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetSquadsCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetSquad(id int) (CM.Squad, error) {
	c, err := s.client()
	if err != nil {
		return CM.Squad{}, err
	}
	reply, err := c.GetSquad(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.Squad{}, mapError(err)
	}
	return convertSquad(reply), nil
}

func (s *Client) UpdateSquad(id int, in CM.SquadUpdate) (CM.Squad, error) {
	c, err := s.client()
	if err != nil {
		return CM.Squad{}, err
	}
	reply, err := c.UpdateSquad(s.callContext(), &pb.SquadUpdateRequest{
		Id:     int32(id),
		Update: &pb.SquadUpdate{Name: in.Name},
	})
	if err != nil {
		return CM.Squad{}, mapError(err)
	}
	return convertSquad(reply), nil
}

func (s *Client) DeleteSquad(id int) (CM.Squad, error) {
	c, err := s.client()
	if err != nil {
		return CM.Squad{}, err
	}
	reply, err := c.DeleteSquad(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.Squad{}, mapError(err)
	}
	return convertSquad(reply), nil
}

func (s *Client) CreateNode(in CM.NodeCreate) (CM.Node, error) {
	c, err := s.client()
	if err != nil {
		return CM.Node{}, err
	}
	reply, err := c.CreateNode(s.callContext(), &pb.NodeCreate{
		Uuid:     in.UUID,
		Name:     in.Name,
		SquadIds: toInt32Slice(in.SquadIDs),
	})
	if err != nil {
		return CM.Node{}, mapError(err)
	}
	return convertNode(reply), nil
}

func (s *Client) GetNodes(filters map[string][]string) ([]CM.Node, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetNodes(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.Node, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertNode(v)
	}
	return out, nil
}

func (s *Client) GetNodesCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetNodesCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetNode(uuid string) (CM.Node, error) {
	c, err := s.client()
	if err != nil {
		return CM.Node{}, err
	}
	reply, err := c.GetNode(s.callContext(), &pb.UuidRequest{Uuid: uuid})
	if err != nil {
		return CM.Node{}, mapError(err)
	}
	return convertNode(reply), nil
}

func (s *Client) GetNodeStatus(uuid string) (string, error) {
	c, err := s.client()
	if err != nil {
		return "", err
	}
	reply, err := c.GetNodeStatus(s.callContext(), &pb.UuidRequest{Uuid: uuid})
	if err != nil {
		return "", mapError(err)
	}
	return reply.GetStatus(), nil
}

func (s *Client) UpdateNode(uuid string, in CM.NodeUpdate) (CM.Node, error) {
	c, err := s.client()
	if err != nil {
		return CM.Node{}, err
	}
	reply, err := c.UpdateNode(s.callContext(), &pb.NodeUpdateRequest{
		Uuid:   uuid,
		Update: &pb.NodeUpdate{Name: in.Name},
	})
	if err != nil {
		return CM.Node{}, mapError(err)
	}
	return convertNode(reply), nil
}

func (s *Client) DeleteNode(uuid string) (CM.Node, error) {
	c, err := s.client()
	if err != nil {
		return CM.Node{}, err
	}
	reply, err := c.DeleteNode(s.callContext(), &pb.UuidRequest{Uuid: uuid})
	if err != nil {
		return CM.Node{}, mapError(err)
	}
	return convertNode(reply), nil
}

func (s *Client) CreateUser(in CM.UserCreate) (CM.User, error) {
	c, err := s.client()
	if err != nil {
		return CM.User{}, err
	}
	reply, err := c.CreateUser(s.callContext(), &pb.UserCreate{
		SquadIds:       toInt32Slice(in.SquadIDs),
		Username:       in.Username,
		Inbound:        in.Inbound,
		Type:           in.Type,
		Uuid:           in.UUID,
		Password:       in.Password,
		Secret:         in.Secret,
		AuthorizedKeys: in.AuthorizedKeys,
		Flow:           in.Flow,
		AlterId:        int32(in.AlterID),
	})
	if err != nil {
		return CM.User{}, mapError(err)
	}
	return convertUser(reply), nil
}

func (s *Client) GetUsers(filters map[string][]string) ([]CM.User, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetUsers(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.User, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertUser(v)
	}
	return out, nil
}

func (s *Client) GetUsersCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetUsersCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetUser(id int) (CM.User, error) {
	c, err := s.client()
	if err != nil {
		return CM.User{}, err
	}
	reply, err := c.GetUser(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.User{}, mapError(err)
	}
	return convertUser(reply), nil
}

func (s *Client) UpdateUser(id int, in CM.UserUpdate) (CM.User, error) {
	c, err := s.client()
	if err != nil {
		return CM.User{}, err
	}
	reply, err := c.UpdateUser(s.callContext(), &pb.UserUpdateRequest{
		Id: int32(id),
		Update: &pb.UserUpdate{
			Uuid:           in.UUID,
			Password:       in.Password,
			Secret:         in.Secret,
			AuthorizedKeys: in.AuthorizedKeys,
			Flow:           in.Flow,
			AlterId:        int32(in.AlterID),
		},
	})
	if err != nil {
		return CM.User{}, mapError(err)
	}
	return convertUser(reply), nil
}

func (s *Client) DeleteUser(id int) (CM.User, error) {
	c, err := s.client()
	if err != nil {
		return CM.User{}, err
	}
	reply, err := c.DeleteUser(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.User{}, mapError(err)
	}
	return convertUser(reply), nil
}

func (s *Client) CreateBandwidthLimiter(in CM.BandwidthLimiterCreate) (CM.BandwidthLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.BandwidthLimiter{}, err
	}
	reply, err := c.CreateBandwidthLimiter(s.callContext(), &pb.BandwidthLimiterCreate{
		SquadIds:       toInt32Slice(in.SquadIDs),
		Username:       in.Username,
		Outbound:       in.Outbound,
		Strategy:       in.Strategy,
		ConnectionType: in.ConnectionType,
		Mode:           in.Mode,
		FlowKeys:       in.FlowKeys,
		Speed:          in.Speed,
	})
	if err != nil {
		return CM.BandwidthLimiter{}, mapError(err)
	}
	return convertBandwidthLimiter(reply), nil
}

func (s *Client) GetBandwidthLimiters(filters map[string][]string) ([]CM.BandwidthLimiter, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetBandwidthLimiters(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.BandwidthLimiter, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertBandwidthLimiter(v)
	}
	return out, nil
}

func (s *Client) GetBandwidthLimitersCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetBandwidthLimitersCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetBandwidthLimiter(id int) (CM.BandwidthLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.BandwidthLimiter{}, err
	}
	reply, err := c.GetBandwidthLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.BandwidthLimiter{}, mapError(err)
	}
	return convertBandwidthLimiter(reply), nil
}

func (s *Client) UpdateBandwidthLimiter(id int, in CM.BandwidthLimiterUpdate) (CM.BandwidthLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.BandwidthLimiter{}, err
	}
	reply, err := c.UpdateBandwidthLimiter(s.callContext(), &pb.BandwidthLimiterUpdateRequest{
		Id: int32(id),
		Update: &pb.BandwidthLimiterUpdate{
			Username:       in.Username,
			Outbound:       in.Outbound,
			Strategy:       in.Strategy,
			ConnectionType: in.ConnectionType,
			Mode:           in.Mode,
			FlowKeys:       in.FlowKeys,
			Speed:          in.Speed,
		},
	})
	if err != nil {
		return CM.BandwidthLimiter{}, mapError(err)
	}
	return convertBandwidthLimiter(reply), nil
}

func (s *Client) DeleteBandwidthLimiter(id int) (CM.BandwidthLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.BandwidthLimiter{}, err
	}
	reply, err := c.DeleteBandwidthLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.BandwidthLimiter{}, mapError(err)
	}
	return convertBandwidthLimiter(reply), nil
}

func (s *Client) CreateTrafficLimiter(in CM.TrafficLimiterCreate) (CM.TrafficLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.TrafficLimiter{}, err
	}
	reply, err := c.CreateTrafficLimiter(s.callContext(), &pb.TrafficLimiterCreate{
		SquadIds: toInt32Slice(in.SquadIDs),
		Username: in.Username,
		Outbound: in.Outbound,
		Strategy: in.Strategy,
		Mode:     in.Mode,
		Quota:    in.Quota,
	})
	if err != nil {
		return CM.TrafficLimiter{}, mapError(err)
	}
	return convertTrafficLimiter(reply), nil
}

func (s *Client) GetTrafficLimiters(filters map[string][]string) ([]CM.TrafficLimiter, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetTrafficLimiters(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.TrafficLimiter, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertTrafficLimiter(v)
	}
	return out, nil
}

func (s *Client) GetTrafficLimitersCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetTrafficLimitersCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetTrafficLimiter(id int) (CM.TrafficLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.TrafficLimiter{}, err
	}
	reply, err := c.GetTrafficLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.TrafficLimiter{}, mapError(err)
	}
	return convertTrafficLimiter(reply), nil
}

func (s *Client) UpdateTrafficLimiter(id int, in CM.TrafficLimiterUpdate) (CM.TrafficLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.TrafficLimiter{}, err
	}
	reply, err := c.UpdateTrafficLimiter(s.callContext(), &pb.TrafficLimiterUpdateRequest{
		Id: int32(id),
		Update: &pb.TrafficLimiterUpdate{
			Username: in.Username,
			Outbound: in.Outbound,
			Strategy: in.Strategy,
			Mode:     in.Mode,
			Quota:    in.Quota,
		},
	})
	if err != nil {
		return CM.TrafficLimiter{}, mapError(err)
	}
	return convertTrafficLimiter(reply), nil
}

func (s *Client) UpdateTrafficLimiterUsed(_ int, _ uint64) (CM.TrafficLimiter, error) {
	return CM.TrafficLimiter{}, E.New("UpdateTrafficLimiterUsed not implemented over gRPC")
}

func (s *Client) DeleteTrafficLimiter(id int) (CM.TrafficLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.TrafficLimiter{}, err
	}
	reply, err := c.DeleteTrafficLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.TrafficLimiter{}, mapError(err)
	}
	return convertTrafficLimiter(reply), nil
}

func (s *Client) CreateConnectionLimiter(in CM.ConnectionLimiterCreate) (CM.ConnectionLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.ConnectionLimiter{}, err
	}
	reply, err := c.CreateConnectionLimiter(s.callContext(), &pb.ConnectionLimiterCreate{
		SquadIds:       toInt32Slice(in.SquadIDs),
		Username:       in.Username,
		Outbound:       in.Outbound,
		Strategy:       in.Strategy,
		ConnectionType: in.ConnectionType,
		LockType:       in.LockType,
		Count:          in.Count,
	})
	if err != nil {
		return CM.ConnectionLimiter{}, mapError(err)
	}
	return convertConnectionLimiter(reply), nil
}

func (s *Client) GetConnectionLimiters(filters map[string][]string) ([]CM.ConnectionLimiter, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetConnectionLimiters(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.ConnectionLimiter, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertConnectionLimiter(v)
	}
	return out, nil
}

func (s *Client) GetConnectionLimitersCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetConnectionLimitersCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetConnectionLimiter(id int) (CM.ConnectionLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.ConnectionLimiter{}, err
	}
	reply, err := c.GetConnectionLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.ConnectionLimiter{}, mapError(err)
	}
	return convertConnectionLimiter(reply), nil
}

func (s *Client) UpdateConnectionLimiter(id int, in CM.ConnectionLimiterUpdate) (CM.ConnectionLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.ConnectionLimiter{}, err
	}
	reply, err := c.UpdateConnectionLimiter(s.callContext(), &pb.ConnectionLimiterUpdateRequest{
		Id: int32(id),
		Update: &pb.ConnectionLimiterUpdate{
			Username:       in.Username,
			Outbound:       in.Outbound,
			Strategy:       in.Strategy,
			ConnectionType: in.ConnectionType,
			LockType:       in.LockType,
			Count:          in.Count,
		},
	})
	if err != nil {
		return CM.ConnectionLimiter{}, mapError(err)
	}
	return convertConnectionLimiter(reply), nil
}

func (s *Client) DeleteConnectionLimiter(id int) (CM.ConnectionLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.ConnectionLimiter{}, err
	}
	reply, err := c.DeleteConnectionLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.ConnectionLimiter{}, mapError(err)
	}
	return convertConnectionLimiter(reply), nil
}

func (s *Client) CreateRateLimiter(in CM.RateLimiterCreate) (CM.RateLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.RateLimiter{}, err
	}
	reply, err := c.CreateRateLimiter(s.callContext(), &pb.RateLimiterCreate{
		SquadIds:       toInt32Slice(in.SquadIDs),
		Username:       in.Username,
		Outbound:       in.Outbound,
		Strategy:       in.Strategy,
		ConnectionType: in.ConnectionType,
		Count:          in.Count,
		Interval:       in.Interval,
	})
	if err != nil {
		return CM.RateLimiter{}, mapError(err)
	}
	return convertRateLimiter(reply), nil
}

func (s *Client) GetRateLimiters(filters map[string][]string) ([]CM.RateLimiter, error) {
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	reply, err := c.GetRateLimiters(s.callContext(), convertFilters(filters))
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]CM.RateLimiter, len(reply.GetValues()))
	for i, v := range reply.GetValues() {
		out[i] = convertRateLimiter(v)
	}
	return out, nil
}

func (s *Client) GetRateLimitersCount(filters map[string][]string) (int, error) {
	c, err := s.client()
	if err != nil {
		return 0, err
	}
	reply, err := c.GetRateLimitersCount(s.callContext(), convertFilters(filters))
	if err != nil {
		return 0, mapError(err)
	}
	return int(reply.GetCount()), nil
}

func (s *Client) GetRateLimiter(id int) (CM.RateLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.RateLimiter{}, err
	}
	reply, err := c.GetRateLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.RateLimiter{}, mapError(err)
	}
	return convertRateLimiter(reply), nil
}

func (s *Client) UpdateRateLimiter(id int, in CM.RateLimiterUpdate) (CM.RateLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.RateLimiter{}, err
	}
	reply, err := c.UpdateRateLimiter(s.callContext(), &pb.RateLimiterUpdateRequest{
		Id: int32(id),
		Update: &pb.RateLimiterUpdate{
			Username:       in.Username,
			Outbound:       in.Outbound,
			Strategy:       in.Strategy,
			ConnectionType: in.ConnectionType,
			Count:          in.Count,
			Interval:       in.Interval,
		},
	})
	if err != nil {
		return CM.RateLimiter{}, mapError(err)
	}
	return convertRateLimiter(reply), nil
}

func (s *Client) DeleteRateLimiter(id int) (CM.RateLimiter, error) {
	c, err := s.client()
	if err != nil {
		return CM.RateLimiter{}, err
	}
	reply, err := c.DeleteRateLimiter(s.callContext(), &pb.IdRequest{Id: int32(id)})
	if err != nil {
		return CM.RateLimiter{}, mapError(err)
	}
	return convertRateLimiter(reply), nil
}
