package node

import (
	"context"
	"errors"
	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/spiffe/control-plane/api/node/pb"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	fetchBootstrapSVID grpctransport.Handler
	fetchNodeSVID      grpctransport.Handler
	fetchSVID          grpctransport.Handler
	fetchCPBundle      grpctransport.Handler
}

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(endpoints Endpoints) (req pb.NodeServer) {
	req = &grpcServer{
		fetchBootstrapSVID: grpctransport.NewServer(
			endpoints.FetchBootstrapSVIDEndpoint,
			DecodeGRPCFetchBootstrapSVIDRequest,
			EncodeGRPCFetchBootstrapSVIDResponse,
		),

		fetchNodeSVID: grpctransport.NewServer(
			endpoints.FetchNodeSVIDEndpoint,
			DecodeGRPCFetchNodeSVIDRequest,
			EncodeGRPCFetchNodeSVIDResponse,
		),

		fetchSVID: grpctransport.NewServer(
			endpoints.FetchSVIDEndpoint,
			DecodeGRPCFetchSVIDRequest,
			EncodeGRPCFetchSVIDResponse,
		),

		fetchCPBundle: grpctransport.NewServer(
			endpoints.FetchCPBundleEndpoint,
			DecodeGRPCFetchCPBundleRequest,
			EncodeGRPCFetchCPBundleResponse,
		),
	}
	return req
}

// DecodeGRPCFetchBootstrapSVIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchBootstrapSVIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchBootstrapSVID' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchBootstrapSVIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchBootstrapSVIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchBootstrapSVID' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchBootstrapSVID(ctx oldcontext.Context, req *pb.FetchBootstrapSVIDRequest) (rep *pb.FetchBootstrapSVIDResponse, err error) {
	_, rp, err := s.fetchBootstrapSVID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchBootstrapSVIDResponse)
	return rep, err
}

// DecodeGRPCFetchNodeSVIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchNodeSVIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchNodeSVID' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchNodeSVIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchNodeSVIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchNodeSVID' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchNodeSVID(ctx oldcontext.Context, req *pb.FetchNodeSVIDRequest) (rep *pb.FetchNodeSVIDResponse, err error) {
	_, rp, err := s.fetchNodeSVID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchNodeSVIDResponse)
	return rep, err
}

// DecodeGRPCFetchSVIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchSVIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchSVID' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchSVIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchSVIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchSVID' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchSVID(ctx oldcontext.Context, req *pb.FetchSVIDRequest) (rep *pb.FetchSVIDResponse, err error) {
	_, rp, err := s.fetchSVID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchSVIDResponse)
	return rep, err
}

// DecodeGRPCFetchCPBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchCPBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchCPBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchCPBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchCPBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchCPBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchCPBundle(ctx oldcontext.Context, req *pb.FetchCPBundleRequest) (rep *pb.FetchCPBundleResponse, err error) {
	_, rp, err := s.fetchCPBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.FetchCPBundleResponse)
	return rep, err
}
