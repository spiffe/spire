package registration

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/spiffe/control-plane/api/registration/pb"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	createFederatedEntry  grpctransport.Handler
	createFederatedBundle grpctransport.Handler
	listFederatedBundles  grpctransport.Handler
	updateFederatedBundle grpctransport.Handler
	deleteFederatedBundle grpctransport.Handler
	createEntry           grpctransport.Handler
	listAttestorEntries   grpctransport.Handler
	listSelectorEntries   grpctransport.Handler
	listSpiffeEntries     grpctransport.Handler
	deleteEntry           grpctransport.Handler
}

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(endpoints Endpoints) (req pb.RegistrationServer) {
	req = &grpcServer{
		createFederatedEntry: grpctransport.NewServer(
			endpoints.CreateFederatedEntryEndpoint,
			DecodeGRPCCreateFederatedEntryRequest,
			EncodeGRPCCreateFederatedEntryResponse,
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

		createEntry: grpctransport.NewServer(
			endpoints.CreateEntryEndpoint,
			DecodeGRPCCreateEntryRequest,
			EncodeGRPCCreateEntryResponse,
		),

		listAttestorEntries: grpctransport.NewServer(
			endpoints.ListAttestorEntriesEndpoint,
			DecodeGRPCListAttestorEntriesRequest,
			EncodeGRPCListAttestorEntriesResponse,
		),

		listSelectorEntries: grpctransport.NewServer(
			endpoints.ListSelectorEntriesEndpoint,
			DecodeGRPCListSelectorEntriesRequest,
			EncodeGRPCListSelectorEntriesResponse,
		),

		listSpiffeEntries: grpctransport.NewServer(
			endpoints.ListSpiffeEntriesEndpoint,
			DecodeGRPCListSpiffeEntriesRequest,
			EncodeGRPCListSpiffeEntriesResponse,
		),

		deleteEntry: grpctransport.NewServer(
			endpoints.DeleteEntryEndpoint,
			DecodeGRPCDeleteEntryRequest,
			EncodeGRPCDeleteEntryResponse,
		),
	}
	return req
}

// DecodeGRPCCreateFederatedEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCCreateFederatedEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'CreateFederatedEntry' Decoder is not impelement")
	return req, err
}

// EncodeGRPCCreateFederatedEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCCreateFederatedEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'CreateFederatedEntry' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) CreateFederatedEntry(ctx oldcontext.Context, req *pb.CreateFederatedEntryRequest) (rep *pb.CreateFederatedEntryResponse, err error) {
	_, rp, err := s.createFederatedEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.CreateFederatedEntryResponse)
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

// DecodeGRPCListAttestorEntriesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListAttestorEntriesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListAttestorEntries' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListAttestorEntriesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListAttestorEntriesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListAttestorEntries' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListAttestorEntries(ctx oldcontext.Context, req *pb.ListAttestorEntriesRequest) (rep *pb.ListAttestorEntriesResponse, err error) {
	_, rp, err := s.listAttestorEntries.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListAttestorEntriesResponse)
	return rep, err
}

// DecodeGRPCListSelectorEntriesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListSelectorEntriesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListSelectorEntries' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListSelectorEntriesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListSelectorEntriesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListSelectorEntries' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListSelectorEntries(ctx oldcontext.Context, req *pb.ListSelectorEntriesRequest) (rep *pb.ListSelectorEntriesResponse, err error) {
	_, rp, err := s.listSelectorEntries.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListSelectorEntriesResponse)
	return rep, err
}

// DecodeGRPCListSpiffeEntriesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListSpiffeEntriesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListSpiffeEntries' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListSpiffeEntriesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListSpiffeEntriesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListSpiffeEntries' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListSpiffeEntries(ctx oldcontext.Context, req *pb.ListSpiffeEntriesRequest) (rep *pb.ListSpiffeEntriesResponse, err error) {
	_, rp, err := s.listSpiffeEntries.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListSpiffeEntriesResponse)
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
