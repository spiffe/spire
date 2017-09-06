package workload

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	pb "github.com/spiffe/spire/pkg/api/workload"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	fetchSVIDBundle       grpctransport.Handler
	fetchSVIDBundles      grpctransport.Handler
	fetchFederatedBundle  grpctransport.Handler
	fetchFederatedBundles grpctransport.Handler
}

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(endpoints Endpoints) (req pb.WorkloadServer) {
	req = &grpcServer{
		fetchSVIDBundle: grpctransport.NewServer(
			endpoints.FetchSVIDBundleEndpoint,
			DecodeGRPCFetchSVIDBundleRequest,
			EncodeGRPCFetchSVIDBundleResponse,
		),

		fetchSVIDBundles: grpctransport.NewServer(
			endpoints.FetchSVIDBundlesEndpoint,
			DecodeGRPCFetchSVIDBundlesRequest,
			EncodeGRPCFetchSVIDBundlesResponse,
		),

		fetchFederatedBundle: grpctransport.NewServer(
			endpoints.FetchFederatedBundleEndpoint,
			DecodeGRPCFetchFederatedBundleRequest,
			EncodeGRPCFetchFederatedBundleResponse,
		),

		fetchFederatedBundles: grpctransport.NewServer(
			endpoints.FetchFederatedBundlesEndpoint,
			DecodeGRPCFetchFederatedBundlesRequest,
			EncodeGRPCFetchFederatedBundlesResponse,
		),
	}
	return req
}

// DecodeGRPCFetchSVIDBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchSVIDBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchSVIDBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchSVIDBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchSVIDBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchSVIDBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchSVIDBundle(ctx oldcontext.Context, req *pb.FetchSVIDBundleRequest) (rep *pb.FetchSVIDBundleResponse, err error) {
	_, rp, err := s.fetchSVIDBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchSVIDBundleResponse)
	return rep, err
}

// DecodeGRPCFetchSVIDBundlesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchSVIDBundlesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchSVIDBundles' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchSVIDBundlesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchSVIDBundlesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchSVIDBundles' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchSVIDBundles(ctx oldcontext.Context, req *pb.Empty) (rep *pb.FetchSVIDBundlesResponse, err error) {
	_, rp, err := s.fetchSVIDBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchSVIDBundlesResponse)
	return rep, err
}

// DecodeGRPCFetchFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchFederatedBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchFederatedBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchFederatedBundle(ctx oldcontext.Context, req *pb.FetchFederatedBundleRequest) (rep *pb.FetchFederatedBundleResponse, err error) {
	_, rp, err := s.fetchFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchFederatedBundleResponse)
	return rep, err
}

// DecodeGRPCFetchFederatedBundlesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchFederatedBundlesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchFederatedBundles' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchFederatedBundlesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchFederatedBundlesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchFederatedBundles' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchFederatedBundles(ctx oldcontext.Context, req *pb.Empty) (rep *pb.FetchFederatedBundlesResponse, err error) {
	_, rp, err := s.fetchFederatedBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchFederatedBundlesResponse)
	return rep, err
}
