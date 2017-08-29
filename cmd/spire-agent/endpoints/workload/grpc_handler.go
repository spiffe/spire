package workload

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	pb "github.com/spiffe/sri/pkg/api/workload"
	"github.com/spiffe/sri/pkg/common"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	fetchBundles    grpctransport.Handler
	fetchAllBundles grpctransport.Handler
}

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(endpoints Endpoints) (req pb.WorkloadServer) {
	req = &grpcServer{
		fetchBundles: grpctransport.NewServer(
			endpoints.FetchBundlesEndpoint,
			DecodeGRPCFetchBundlesRequest,
			EncodeGRPCFetchBundlesResponse,
		),

		fetchAllBundles: grpctransport.NewServer(
			endpoints.FetchAllBundlesEndpoint,
			DecodeGRPCFetchAllBundlesRequest,
			EncodeGRPCFetchAllBundlesResponse,
		),
	}
	return req
}

// DecodeGRPCFetchSVIDBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchBundlesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchSVIDBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchSVIDBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchBundlesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchSVIDBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchBundles(ctx oldcontext.Context, req *pb.SpiffeId) (rep *pb.Bundles, err error) {
	_, rp, err := s.fetchBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.Bundles)
	return rep, err
}

// DecodeGRPCFetchSVIDBundlesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchAllBundlesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchSVIDBundles' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchSVIDBundlesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchAllBundlesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchSVIDBundles' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchAllBundles(ctx oldcontext.Context, req *common.Empty) (rep *pb.Bundles, err error) {
	_, rp, err := s.fetchAllBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.Bundles)
	return rep, err
}
