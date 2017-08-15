package registration

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	pb "github.com/spiffe/sri/control_plane/api/registration/proto"
	oldcontext "golang.org/x/net/context"
)

type grpcServer struct {
	createEntry           grpctransport.Handler
	deleteEntry           grpctransport.Handler
	fetchEntry            grpctransport.Handler
	updateEntry           grpctransport.Handler
	listByParentID        grpctransport.Handler
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

		fetchEntry: grpctransport.NewServer(
			endpoints.FetchEntryEndpoint,
			DecodeGRPCFetchEntryRequest,
			EncodeGRPCFetchEntryResponse,
		),

		updateEntry: grpctransport.NewServer(
			endpoints.UpdateEntryEndpoint,
			DecodeGRPCUpdateEntryRequest,
			EncodeGRPCUpdateEntryResponse,
		),

		listByParentID: grpctransport.NewServer(
			endpoints.ListByParentIDEndpoint,
			DecodeGRPCListByParentIDRequest,
			EncodeGRPCListByParentIDResponse,
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

func (s *grpcServer) CreateEntry(ctx oldcontext.Context, req *pb.RegisteredEntry) (rep *pb.RegisteredEntryID, err error) {
	_, rp, err := s.createEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntryID)
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

func (s *grpcServer) DeleteEntry(ctx oldcontext.Context, req *pb.RegisteredEntryID) (rep *pb.RegisteredEntry, err error) {
	_, rp, err := s.deleteEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntry)
	return rep, err
}

// DecodeGRPCFetchEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCFetchEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'FetchEntry' Decoder is not impelement")
	return req, err
}

// EncodeGRPCFetchEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCFetchEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'FetchEntry' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) FetchEntry(ctx oldcontext.Context, req *pb.RegisteredEntryID) (rep *pb.RegisteredEntry, err error) {
	_, rp, err := s.fetchEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntry)
	return rep, err
}

// DecodeGRPCUpdateEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCUpdateEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'UpdateEntry' Decoder is not impelement")
	return req, err
}

// EncodeGRPCUpdateEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCUpdateEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'UpdateEntry' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) UpdateEntry(ctx oldcontext.Context, req *pb.UpdateEntryRequest) (rep *pb.RegisteredEntry, err error) {
	_, rp, err := s.updateEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntry)
	return rep, err
}

// DecodeGRPCListByParentIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
// TODO: Do not forget to implement the decoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func DecodeGRPCListByParentIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	err = errors.New("'ListByParentID' Decoder is not impelement")
	return req, err
}

// EncodeGRPCListByParentIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
// TODO: Do not forget to implement the encoder, you can find an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/transport_grpc.go#L62-L65
func EncodeGRPCListByParentIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	err = errors.New("'ListByParentID' Encoder is not impelement")
	return res, err
}

func (s *grpcServer) ListByParentID(ctx oldcontext.Context, req *pb.ParentID) (rep *pb.RegisteredEntries, err error) {
	_, rp, err := s.listByParentID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntries)
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

func (s *grpcServer) ListBySelector(ctx oldcontext.Context, req *pb.Selector) (rep *pb.RegisteredEntries, err error) {
	_, rp, err := s.listBySelector.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntries)
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

func (s *grpcServer) ListBySpiffeID(ctx oldcontext.Context, req *pb.SpiffeID) (rep *pb.RegisteredEntries, err error) {
	_, rp, err := s.listBySpiffeID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegisteredEntries)
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

func (s *grpcServer) CreateFederatedBundle(ctx oldcontext.Context, req *pb.CreateFederatedBundleRequest) (rep *pb.Empty, err error) {
	_, rp, err := s.createFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.Empty)
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

func (s *grpcServer) ListFederatedBundles(ctx oldcontext.Context, req *pb.Empty) (rep *pb.ListFederatedBundlesReply, err error) {
	_, rp, err := s.listFederatedBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListFederatedBundlesReply)
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

func (s *grpcServer) UpdateFederatedBundle(ctx oldcontext.Context, req *pb.FederatedBundle) (rep *pb.Empty, err error) {
	_, rp, err := s.updateFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.Empty)
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

func (s *grpcServer) DeleteFederatedBundle(ctx oldcontext.Context, req *pb.FederatedSpiffeID) (rep *pb.Empty, err error) {
	_, rp, err := s.deleteFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.Empty)
	return rep, err
}
