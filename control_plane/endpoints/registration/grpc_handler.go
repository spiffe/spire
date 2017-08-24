package registration

import (
	"context"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/spiffe/sri/common"
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
func DecodeGRPCCreateEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*common.RegistrationEntry)
	return CreateEntryRequest{Request: *temp}, err
}

// EncodeGRPCCreateEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCCreateEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(CreateEntryResponse)
	return &temp.Reply, err
}

func (s *grpcServer) CreateEntry(ctx oldcontext.Context, req *common.RegistrationEntry) (rep *pb.RegistrationEntryID, err error) {
	_, rp, err := s.createEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.RegistrationEntryID)
	return rep, err
}

// DecodeGRPCDeleteEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCDeleteEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.RegistrationEntryID)
	return DeleteEntryRequest{Request: *temp}, err
}

// EncodeGRPCDeleteEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCDeleteEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(DeleteEntryResponse)
	return &temp.Reply, err
}

func (s *grpcServer) DeleteEntry(ctx oldcontext.Context, req *pb.RegistrationEntryID) (rep *common.RegistrationEntry, err error) {
	_, rp, err := s.deleteEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.RegistrationEntry)
	return rep, err
}

// DecodeGRPCFetchEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCFetchEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.RegistrationEntryID)
	return FetchEntryRequest{Request: *temp}, err
}

// EncodeGRPCFetchEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCFetchEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(FetchEntryResponse)
	return &temp.Reply, err
}

func (s *grpcServer) FetchEntry(ctx oldcontext.Context, req *pb.RegistrationEntryID) (rep *common.RegistrationEntry, err error) {
	_, rp, err := s.fetchEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.RegistrationEntry)
	return rep, err
}

// DecodeGRPCUpdateEntryRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCUpdateEntryRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.UpdateEntryRequest)
	return UpdateEntryRequest{Request: *temp}, err
}

// EncodeGRPCUpdateEntryResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCUpdateEntryResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(UpdateEntryResponse)
	return &temp.Reply, err
}

func (s *grpcServer) UpdateEntry(ctx oldcontext.Context, req *pb.UpdateEntryRequest) (rep *common.RegistrationEntry, err error) {
	_, rp, err := s.updateEntry.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.RegistrationEntry)
	return rep, err
}

// DecodeGRPCListByParentIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCListByParentIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.ParentID)
	return ListByParentIDRequest{Request: *temp}, err
}

// EncodeGRPCListByParentIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCListByParentIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(ListByParentIDResponse)
	return &temp.Reply, err
}

func (s *grpcServer) ListByParentID(ctx oldcontext.Context, req *pb.ParentID) (rep *common.RegistrationEntries, err error) {
	_, rp, err := s.listByParentID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.RegistrationEntries)
	return rep, err
}

// DecodeGRPCListBySelectorRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCListBySelectorRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*common.Selector)
	return ListBySelectorRequest{Request: *temp}, err
}

// EncodeGRPCListBySelectorResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCListBySelectorResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(ListBySelectorResponse)
	return &temp.Reply, err
}

func (s *grpcServer) ListBySelector(ctx oldcontext.Context, req *common.Selector) (rep *common.RegistrationEntries, err error) {
	_, rp, err := s.listBySelector.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.RegistrationEntries)
	return rep, err
}

// DecodeGRPCListBySpiffeIDRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCListBySpiffeIDRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.SpiffeID)
	return ListBySpiffeIDRequest{Request: *temp}, err
}

// EncodeGRPCListBySpiffeIDResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCListBySpiffeIDResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(ListBySpiffeIDResponse)
	return &temp.Reply, err
}

func (s *grpcServer) ListBySpiffeID(ctx oldcontext.Context, req *pb.SpiffeID) (rep *common.RegistrationEntries, err error) {
	_, rp, err := s.listBySpiffeID.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.RegistrationEntries)
	return rep, err
}

// DecodeGRPCCreateFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCCreateFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.CreateFederatedBundleRequest)
	return CreateFederatedBundleRequest{Request: *temp}, err
}

// EncodeGRPCCreateFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCCreateFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(CreateFederatedBundleResponse)
	return &temp.Reply, err
}

func (s *grpcServer) CreateFederatedBundle(ctx oldcontext.Context, req *pb.CreateFederatedBundleRequest) (rep *common.Empty, err error) {
	_, rp, err := s.createFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.Empty)
	return rep, err
}

// DecodeGRPCListFederatedBundlesRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCListFederatedBundlesRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*common.Empty)
	return ListFederatedBundlesRequest{Request: *temp}, err
}

// EncodeGRPCListFederatedBundlesResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCListFederatedBundlesResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(ListFederatedBundlesResponse)
	return &temp.Reply, err
}

func (s *grpcServer) ListFederatedBundles(ctx oldcontext.Context, req *common.Empty) (rep *pb.ListFederatedBundlesReply, err error) {
	_, rp, err := s.listFederatedBundles.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*pb.ListFederatedBundlesReply)
	return rep, err
}

// DecodeGRPCUpdateFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCUpdateFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.FederatedBundle)
	return UpdateFederatedBundleRequest{Request: *temp}, err
}

// EncodeGRPCUpdateFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCUpdateFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(UpdateFederatedBundleResponse)
	return &temp.Reply, err
}

func (s *grpcServer) UpdateFederatedBundle(ctx oldcontext.Context, req *pb.FederatedBundle) (rep *common.Empty, err error) {
	_, rp, err := s.updateFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.Empty)
	return rep, err
}

// DecodeGRPCDeleteFederatedBundleRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request. Primarily useful in a server.
func DecodeGRPCDeleteFederatedBundleRequest(_ context.Context, grpcReq interface{}) (req interface{}, err error) {
	temp := grpcReq.(*pb.FederatedSpiffeID)
	return DeleteFederatedBundleRequest{Request: *temp}, err
}

// EncodeGRPCDeleteFederatedBundleResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply. Primarily useful in a server.
func EncodeGRPCDeleteFederatedBundleResponse(_ context.Context, grpcReply interface{}) (res interface{}, err error) {
	temp := grpcReply.(DeleteFederatedBundleResponse)
	return &temp.Reply, err
}

func (s *grpcServer) DeleteFederatedBundle(ctx oldcontext.Context, req *pb.FederatedSpiffeID) (rep *common.Empty, err error) {
	_, rp, err := s.deleteFederatedBundle.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rep = rp.(*common.Empty)
	return rep, err
}
