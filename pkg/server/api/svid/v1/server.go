package svid

import (
	"context"

	"github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service Service) {
	svid.RegisterSVIDServer(s, server{service: service})
}

type server struct {
	service Service
}

func (s server) MintX509SVID(context.Context, *svid.MintX509SVIDRequest) (*svid.MintX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) MintJWTSVID(context.Context, *svid.MintJWTSVIDRequest) (*svid.MintJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) BatchNewX509SVID(context.Context, *svid.BatchNewX509SVIDRequest) (*svid.BatchNewX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) NewJWTSVID(context.Context, *svid.NewJWTSVIDRequest) (*svid.NewJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s server) NewDownstreamX509CA(context.Context, *svid.NewDownstreamX509CARequest) (*svid.NewDownstreamX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
