package server

import (
	"context"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	pb "github.com/spiffe/node-agent/api/server/proto"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	stop       grpctransport.Handler
	pluginInfo grpctransport.Handler
}

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(endpoints Endpoints) (req pb.ServerServer) {
	req = &grpcServer{
		stop: grpctransport.NewServer(
			endpoints.StopEndpoint,
			DecodeGRPCStopRequest,
			EncodeGRPCStopResponse,
		),

		pluginInfo: grpctransport.NewServer(
			endpoints.PluginInfoEndpoint,
			DecodeGRPCPluginInfoRequest,
			EncodeGRPCPluginInfoResponse,
		),
	}
	return req
}

// DecodeGRPCStopRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCStopRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.StopRequest)
	return StopRequest{Request: *temp}, err
}

// EncodeGRPCStopResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCStopResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(StopResponse)
	return &temp.Response, err
}

func (s *grpcServer) Stop(ctx oldcontext.Context, req *pb.StopRequest) (rep *pb.StopReply, err error) {
	_, rp, err := s.stop.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.StopReply)
	return rep, err
}

// DecodeGRPCPluginInfoRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCPluginInfoRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.PluginInfoRequest)
	return PluginInfoRequest{Request: *temp}, err
}

// EncodeGRPCPluginInfoResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCPluginInfoResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(PluginInfoResponse)
	return &temp.Response, err
}

func (s *grpcServer) PluginInfo(ctx oldcontext.Context, req *pb.PluginInfoRequest) (rep *pb.PluginInfoReply, err error) {
	_, rp, err := s.pluginInfo.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.PluginInfoReply)
	return rep, err
}