package registration

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/spiffe/control-plane/api/registration/pb"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	createEntry           grpctransport.Handler
	deleteEntry           grpctransport.Handler
	listByAttestor        grpctransport.Handler
	listBySelector        grpctransport.Handler
	listBySpiffeID        grpctransport.Handler
	createFederatedBundle grpctransport.Handler
	listFederatedBundles  grpctransport.Handler
	updateFederatedBundle grpctransport.Handler
	deleteFederatedBundle grpctransport.Handler
}

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(endpoints Endpoints) (req pb.RegistrationServer) {
	req = &grpcServer{
		createEntry: grpctransport.NewServer(
			endpoints.CreateEntryEndpoint,
			DecodeGRPCCreateEntryRequest,
			EncodeGRPCCreateEntryResponse,
		),

		deleteEntry: grpctransport.NewServer(
			endpoints.DeleteEntryEndpoint,
			DecodeGRPCDeleteEntryRequest,
			EncodeGRPCDeleteEntryResponse,
		),

		listByAttestor: grpctransport.NewServer(
			endpoints.ListByAttestorEndpoint,
			DecodeGRPCListByAttestorRequest,
			EncodeGRPCListByAttestorResponse,
		),

		listBySelector: grpctransport.NewServer(
			endpoints.ListBySelectorEndpoint,
			DecodeGRPCListBySelectorRequest,
			EncodeGRPCListBySelectorResponse,
		),

		listBySpiffeID: grpctransport.NewServer(
			endpoints.ListBySpiffeIDEndpoint,
			DecodeGRPCListBySpiffeIDRequest,
			EncodeGRPCListBySpiffeIDResponse,
		),

		createFederatedBundle: grpctransport.NewServer(
			endpoints.CreateFederatedBundleEndpoint,
			DecodeGRPCCreateFederatedBundleRequest,
			EncodeGRPCCreateFederatedBundleResponse,
		),

		listFederatedBundles: grpctransport.NewServer(
			endpoints.ListFederatedBundlesEndpoint,
			DecodeGRPCListFederatedBundlesRequest,
			EncodeGRPCListFederatedBundlesResponse,
		),

		updateFederatedBundle: grpctransport.NewServer(
			endpoints.UpdateFederatedBundleEndpoint,
			DecodeGRPCUpdateFederatedBundleRequest,
			EncodeGRPCUpdateFederatedBundleResponse,
		),

		deleteFederatedBundle: grpctransport.NewServer(
			endpoints.DeleteFederatedBundleEndpoint,
			DecodeGRPCDeleteFederatedBundleRequest,
			EncodeGRPCDeleteFederatedBundleResponse,
		),
	}
	return req
}

// DecodeGRPCCreateEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCCreateEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'CreateEntry' Decoder is not impelement")
	return req, err
}

// EncodeGRPCCreateEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCCreateEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'CreateEntry' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) CreateEntry(ctx oldcontext.Context, req *pb.CreateEntryRequest) (rep *pb.CreateEntryResponse, err error) {
	_, rp, err := s.createEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.CreateEntryResponse)
	return rep, err
}

// DecodeGRPCDeleteEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCDeleteEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'DeleteEntry' Decoder is not impelement")
	return req, err
}

// EncodeGRPCDeleteEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCDeleteEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'DeleteEntry' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) DeleteEntry(ctx oldcontext.Context, req *pb.DeleteEntryRequest) (rep *pb.DeleteEntryResponse, err error) {
	_, rp, err := s.deleteEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.DeleteEntryResponse)
	return rep, err
}

// DecodeGRPCListByAttestorRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListByAttestorRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListByAttestor' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListByAttestorResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListByAttestorResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListByAttestor' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListByAttestor(ctx oldcontext.Context, req *pb.ListByAttestorRequest) (rep *pb.ListByAttestorResponse, err error) {
	_, rp, err := s.listByAttestor.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListByAttestorResponse)
	return rep, err
}

// DecodeGRPCListBySelectorRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListBySelectorRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListBySelector' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListBySelectorResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListBySelectorResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListBySelector' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListBySelector(ctx oldcontext.Context, req *pb.ListBySelectorRequest) (rep *pb.ListBySelectorResponse, err error) {
	_, rp, err := s.listBySelector.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListBySelectorResponse)
	return rep, err
}

// DecodeGRPCListBySpiffeIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListBySpiffeIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListBySpiffeID' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListBySpiffeIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListBySpiffeIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListBySpiffeID' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListBySpiffeID(ctx oldcontext.Context, req *pb.ListBySpiffeIDRequest) (rep *pb.ListBySpiffeIDResponse, err error) {
	_, rp, err := s.listBySpiffeID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListBySpiffeIDResponse)
	return rep, err
}

// DecodeGRPCCreateFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCCreateFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'CreateFederatedBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCCreateFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCCreateFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'CreateFederatedBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) CreateFederatedBundle(ctx oldcontext.Context, req *pb.CreateFederatedBundleRequest) (rep *pb.CreateFederatedBundleResponse, err error) {
	_, rp, err := s.createFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.CreateFederatedBundleResponse)
	return rep, err
}

// DecodeGRPCListFederatedBundlesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListFederatedBundlesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListFederatedBundles' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListFederatedBundlesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListFederatedBundlesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListFederatedBundles' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListFederatedBundles(ctx oldcontext.Context, req *pb.ListFederatedBundlesRequest) (rep *pb.ListFederatedBundlesResponse, err error) {
	_, rp, err := s.listFederatedBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListFederatedBundlesResponse)
	return rep, err
}

// DecodeGRPCUpdateFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCUpdateFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'UpdateFederatedBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCUpdateFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCUpdateFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'UpdateFederatedBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) UpdateFederatedBundle(ctx oldcontext.Context, req *pb.UpdateFederatedBundleRequest) (rep *pb.UpdateFederatedBundleResponse, err error) {
	_, rp, err := s.updateFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.UpdateFederatedBundleResponse)
	return rep, err
}

// DecodeGRPCDeleteFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCDeleteFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'DeleteFederatedBundle' Decoder is not impelement")
	return req, err
}

// EncodeGRPCDeleteFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCDeleteFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'DeleteFederatedBundle' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) DeleteFederatedBundle(ctx oldcontext.Context, req *pb.DeleteFederatedBundleRequest) (rep *pb.DeleteFederatedBundleResponse, err error) {
	_, rp, err := s.deleteFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.DeleteFederatedBundleResponse)
	return rep, err
}
