package v2raygrpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
)

type GunService interface {
	Context() context.Context
	Send(*Hunk) error
	Recv() (*Hunk, error)
}

func ServerDesc(name string) grpc.ServiceDesc {
	serviceName := name
	streamName := "Tun"
	if strings.Contains(name, "/") {
		name = strings.TrimPrefix(name, "/")
		lastSlash := strings.LastIndex(name, "/")
		serviceName = name[:lastSlash]
		streamName = name[lastSlash+1:]
	}
	return grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*GunServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    streamName,
				Handler:       _GunService_Tun_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func (c *gunServiceClient) TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error) {
	path := "/" + name + "/Tun"
	if strings.Contains(name, "/") {
		path = name
	}
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name).Streams[0], path, opts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Hunk, Hunk]{ClientStream: stream}
	return x, nil
}

var _ GunServiceCustomNameClient = (*gunServiceClient)(nil)

type GunServiceCustomNameClient interface {
	TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error)
	Tun(ctx context.Context, opts ...grpc.CallOption) (GunService_TunClient, error)
}

func RegisterGunServiceCustomNameServer(s *grpc.Server, srv GunServiceServer, name string) {
	desc := ServerDesc(name)
	s.RegisterService(&desc, srv)
}
