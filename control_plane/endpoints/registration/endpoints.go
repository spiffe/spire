package registration

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/spiffe/sri/pkg/common"
	proto "github.com/spiffe/sri/control_plane/api/registration/proto"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	CreateEntryEndpoint           endpoint.Endpoint
	DeleteEntryEndpoint           endpoint.Endpoint
	FetchEntryEndpoint            endpoint.Endpoint
	UpdateEntryEndpoint           endpoint.Endpoint
	ListByParentIDEndpoint        endpoint.Endpoint
	ListBySelectorEndpoint        endpoint.Endpoint
	ListBySpiffeIDEndpoint        endpoint.Endpoint
	CreateFederatedBundleEndpoint endpoint.Endpoint
	ListFederatedBundlesEndpoint  endpoint.Endpoint
	UpdateFederatedBundleEndpoint endpoint.Endpoint
	DeleteFederatedBundleEndpoint endpoint.Endpoint
}
type CreateEntryRequest struct {
	Request common.RegistrationEntry
}
type CreateEntryResponse struct {
	Reply proto.RegistrationEntryID
	Err   error
}
type DeleteEntryRequest struct {
	Request proto.RegistrationEntryID
}
type DeleteEntryResponse struct {
	Reply common.RegistrationEntry
	Err   error
}
type FetchEntryRequest struct {
	Request proto.RegistrationEntryID
}
type FetchEntryResponse struct {
	Reply common.RegistrationEntry
	Err   error
}
type UpdateEntryRequest struct {
	Request proto.UpdateEntryRequest
}
type UpdateEntryResponse struct {
	Reply common.RegistrationEntry
	Err   error
}
type ListByParentIDRequest struct {
	Request proto.ParentID
}
type ListByParentIDResponse struct {
	Reply common.RegistrationEntries
	Err   error
}
type ListBySelectorRequest struct {
	Request common.Selector
}
type ListBySelectorResponse struct {
	Reply common.RegistrationEntries
	Err   error
}
type ListBySpiffeIDRequest struct {
	Request proto.SpiffeID
}
type ListBySpiffeIDResponse struct {
	Reply common.RegistrationEntries
	Err   error
}
type CreateFederatedBundleRequest struct {
	Request proto.CreateFederatedBundleRequest
}
type CreateFederatedBundleResponse struct {
	Reply common.Empty
	Err   error
}
type ListFederatedBundlesRequest struct {
	Request common.Empty
}
type ListFederatedBundlesResponse struct {
	Reply proto.ListFederatedBundlesReply
	Err   error
}
type UpdateFederatedBundleRequest struct {
	Request proto.FederatedBundle
}
type UpdateFederatedBundleResponse struct {
	Reply common.Empty
	Err   error
}
type DeleteFederatedBundleRequest struct {
	Request proto.FederatedSpiffeID
}
type DeleteFederatedBundleResponse struct {
	Reply common.Empty
	Err   error
}

func NewEndpoint(svc RegistrationService) (ep Endpoints) {
	ep.CreateEntryEndpoint = MakeCreateEntryEndpoint(svc)
	ep.DeleteEntryEndpoint = MakeDeleteEntryEndpoint(svc)
	ep.FetchEntryEndpoint = MakeFetchEntryEndpoint(svc)
	ep.UpdateEntryEndpoint = MakeUpdateEntryEndpoint(svc)
	ep.ListByParentIDEndpoint = MakeListByParentIDEndpoint(svc)
	ep.ListBySelectorEndpoint = MakeListBySelectorEndpoint(svc)
	ep.ListBySpiffeIDEndpoint = MakeListBySpiffeIDEndpoint(svc)
	ep.CreateFederatedBundleEndpoint = MakeCreateFederatedBundleEndpoint(svc)
	ep.ListFederatedBundlesEndpoint = MakeListFederatedBundlesEndpoint(svc)
	ep.UpdateFederatedBundleEndpoint = MakeUpdateFederatedBundleEndpoint(svc)
	ep.DeleteFederatedBundleEndpoint = MakeDeleteFederatedBundleEndpoint(svc)
	return ep
}

// MakeCreateEntryEndpoint returns an endpoint that invokes CreateEntry on the service.
// Primarily useful in a server.
func MakeCreateEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(CreateEntryRequest)
		reply, err := svc.CreateEntry(ctx, req.Request)
		return CreateEntryResponse{Reply: reply, Err: err}, nil
	}
}

// MakeDeleteEntryEndpoint returns an endpoint that invokes DeleteEntry on the service.
// Primarily useful in a server.
func MakeDeleteEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(DeleteEntryRequest)
		reply, err := svc.DeleteEntry(ctx, req.Request)
		return DeleteEntryResponse{Reply: reply, Err: err}, nil
	}
}

// MakeFetchEntryEndpoint returns an endpoint that invokes FetchEntry on the service.
// Primarily useful in a server.
func MakeFetchEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchEntryRequest)
		reply, err := svc.FetchEntry(ctx, req.Request)
		return FetchEntryResponse{Reply: reply, Err: err}, nil
	}
}

// MakeUpdateEntryEndpoint returns an endpoint that invokes UpdateEntry on the service.
// Primarily useful in a server.
func MakeUpdateEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UpdateEntryRequest)
		reply, err := svc.UpdateEntry(ctx, req.Request)
		return UpdateEntryResponse{Reply: reply, Err: err}, nil
	}
}

// MakeListByParentIDEndpoint returns an endpoint that invokes ListByParentID on the service.
// Primarily useful in a server.
func MakeListByParentIDEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListByParentIDRequest)
		reply, err := svc.ListByParentID(ctx, req.Request)
		return ListByParentIDResponse{Reply: reply, Err: err}, nil
	}
}

// MakeListBySelectorEndpoint returns an endpoint that invokes ListBySelector on the service.
// Primarily useful in a server.
func MakeListBySelectorEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListBySelectorRequest)
		reply, err := svc.ListBySelector(ctx, req.Request)
		return ListBySelectorResponse{Reply: reply, Err: err}, nil
	}
}

// MakeListBySpiffeIDEndpoint returns an endpoint that invokes ListBySpiffeID on the service.
// Primarily useful in a server.
func MakeListBySpiffeIDEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListBySpiffeIDRequest)
		reply, err := svc.ListBySpiffeID(ctx, req.Request)
		return ListBySpiffeIDResponse{Reply: reply, Err: err}, nil
	}
}

// MakeCreateFederatedBundleEndpoint returns an endpoint that invokes CreateFederatedBundle on the service.
// Primarily useful in a server.
func MakeCreateFederatedBundleEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(CreateFederatedBundleRequest)
		reply, err := svc.CreateFederatedBundle(ctx, req.Request)
		return CreateFederatedBundleResponse{Reply: reply, Err: err}, nil
	}
}

// MakeListFederatedBundlesEndpoint returns an endpoint that invokes ListFederatedBundles on the service.
// Primarily useful in a server.
func MakeListFederatedBundlesEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListFederatedBundlesRequest)
		reply, err := svc.ListFederatedBundles(ctx, req.Request)
		return ListFederatedBundlesResponse{Reply: reply, Err: err}, nil
	}
}

// MakeUpdateFederatedBundleEndpoint returns an endpoint that invokes UpdateFederatedBundle on the service.
// Primarily useful in a server.
func MakeUpdateFederatedBundleEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UpdateFederatedBundleRequest)
		reply, err := svc.UpdateFederatedBundle(ctx, req.Request)
		return UpdateFederatedBundleResponse{Reply: reply, Err: err}, nil
	}
}

// MakeDeleteFederatedBundleEndpoint returns an endpoint that invokes DeleteFederatedBundle on the service.
// Primarily useful in a server.
func MakeDeleteFederatedBundleEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(DeleteFederatedBundleRequest)
		reply, err := svc.DeleteFederatedBundle(ctx, req.Request)
		return DeleteFederatedBundleResponse{Reply: reply, Err: err}, nil
	}
}
