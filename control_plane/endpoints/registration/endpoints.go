package registration

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/spiffe/control-plane/api/registration/pb"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	CreateFederatedEntryEndpoint  endpoint.Endpoint
	CreateFederatedBundleEndpoint endpoint.Endpoint
	ListFederatedBundlesEndpoint  endpoint.Endpoint
	UpdateFederatedBundleEndpoint endpoint.Endpoint
	DeleteFederatedBundleEndpoint endpoint.Endpoint
	CreateEntryEndpoint           endpoint.Endpoint
	ListAttestorEntriesEndpoint   endpoint.Endpoint
	ListSelectorEntriesEndpoint   endpoint.Endpoint
	ListSpiffeEntriesEndpoint     endpoint.Endpoint
	DeleteEntryEndpoint           endpoint.Endpoint
}
type CreateFederatedEntryRequest struct {
	Request pb.CreateFederatedEntryRequest
}
type CreateFederatedEntryResponse struct {
	Response pb.CreateFederatedEntryResponse
}
type CreateFederatedBundleRequest struct {
	Request pb.CreateFederatedBundleRequest
}
type CreateFederatedBundleResponse struct {
	Response pb.CreateFederatedBundleResponse
}
type ListFederatedBundlesRequest struct {
	Request pb.ListFederatedBundlesRequest
}
type ListFederatedBundlesResponse struct {
	Response pb.ListFederatedBundlesResponse
}
type UpdateFederatedBundleRequest struct {
	Request pb.UpdateFederatedBundleRequest
}
type UpdateFederatedBundleResponse struct {
	Response pb.UpdateFederatedBundleResponse
}
type DeleteFederatedBundleRequest struct {
	Request pb.DeleteFederatedBundleRequest
}
type DeleteFederatedBundleResponse struct {
	Response pb.DeleteFederatedBundleResponse
}
type CreateEntryRequest struct {
	Request pb.CreateEntryRequest
}
type CreateEntryResponse struct {
	Response pb.CreateEntryResponse
}
type ListAttestorEntriesRequest struct {
	Request pb.ListAttestorEntriesRequest
}
type ListAttestorEntriesResponse struct {
	Response pb.ListAttestorEntriesResponse
}
type ListSelectorEntriesRequest struct {
	Request pb.ListSelectorEntriesRequest
}
type ListSelectorEntriesResponse struct {
	Response pb.ListSelectorEntriesResponse
}
type ListSpiffeEntriesRequest struct {
	Request pb.ListSpiffeEntriesRequest
}
type ListSpiffeEntriesResponse struct {
	Response pb.ListSpiffeEntriesResponse
}
type DeleteEntryRequest struct {
	Request pb.DeleteEntryRequest
}
type DeleteEntryResponse struct {
	Response pb.DeleteEntryResponse
}

func NewEndpoint(svc RegistrationService) (ep Endpoints) {
	ep.CreateFederatedEntryEndpoint = MakeCreateFederatedEntryEndpoint(svc)
	ep.CreateFederatedBundleEndpoint = MakeCreateFederatedBundleEndpoint(svc)
	ep.ListFederatedBundlesEndpoint = MakeListFederatedBundlesEndpoint(svc)
	ep.UpdateFederatedBundleEndpoint = MakeUpdateFederatedBundleEndpoint(svc)
	ep.DeleteFederatedBundleEndpoint = MakeDeleteFederatedBundleEndpoint(svc)
	ep.CreateEntryEndpoint = MakeCreateEntryEndpoint(svc)
	ep.ListAttestorEntriesEndpoint = MakeListAttestorEntriesEndpoint(svc)
	ep.ListSelectorEntriesEndpoint = MakeListSelectorEntriesEndpoint(svc)
	ep.ListSpiffeEntriesEndpoint = MakeListSpiffeEntriesEndpoint(svc)
	ep.DeleteEntryEndpoint = MakeDeleteEntryEndpoint(svc)
	return ep
}

// MakeCreateFederatedEntryEndpoint returns an endpoint that invokes CreateFederatedEntry on the service.
// Primarily useful in a server.
func MakeCreateFederatedEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(CreateFederatedEntryRequest)
		response := svc.CreateFederatedEntry(ctx, req.Request)
		return CreateFederatedEntryResponse{Response: response}, nil
	}
}

// MakeCreateFederatedBundleEndpoint returns an endpoint that invokes CreateFederatedBundle on the service.
// Primarily useful in a server.
func MakeCreateFederatedBundleEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(CreateFederatedBundleRequest)
		response := svc.CreateFederatedBundle(ctx, req.Request)
		return CreateFederatedBundleResponse{Response: response}, nil
	}
}

// MakeListFederatedBundlesEndpoint returns an endpoint that invokes ListFederatedBundles on the service.
// Primarily useful in a server.
func MakeListFederatedBundlesEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListFederatedBundlesRequest)
		response := svc.ListFederatedBundles(ctx, req.Request)
		return ListFederatedBundlesResponse{Response: response}, nil
	}
}

// MakeUpdateFederatedBundleEndpoint returns an endpoint that invokes UpdateFederatedBundle on the service.
// Primarily useful in a server.
func MakeUpdateFederatedBundleEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UpdateFederatedBundleRequest)
		response := svc.UpdateFederatedBundle(ctx, req.Request)
		return UpdateFederatedBundleResponse{Response: response}, nil
	}
}

// MakeDeleteFederatedBundleEndpoint returns an endpoint that invokes DeleteFederatedBundle on the service.
// Primarily useful in a server.
func MakeDeleteFederatedBundleEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(DeleteFederatedBundleRequest)
		response := svc.DeleteFederatedBundle(ctx, req.Request)
		return DeleteFederatedBundleResponse{Response: response}, nil
	}
}

// MakeCreateEntryEndpoint returns an endpoint that invokes CreateEntry on the service.
// Primarily useful in a server.
func MakeCreateEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(CreateEntryRequest)
		response := svc.CreateEntry(ctx, req.Request)
		return CreateEntryResponse{Response: response}, nil
	}
}

// MakeListAttestorEntriesEndpoint returns an endpoint that invokes ListAttestorEntries on the service.
// Primarily useful in a server.
func MakeListAttestorEntriesEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListAttestorEntriesRequest)
		response := svc.ListAttestorEntries(ctx, req.Request)
		return ListAttestorEntriesResponse{Response: response}, nil
	}
}

// MakeListSelectorEntriesEndpoint returns an endpoint that invokes ListSelectorEntries on the service.
// Primarily useful in a server.
func MakeListSelectorEntriesEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListSelectorEntriesRequest)
		response := svc.ListSelectorEntries(ctx, req.Request)
		return ListSelectorEntriesResponse{Response: response}, nil
	}
}

// MakeListSpiffeEntriesEndpoint returns an endpoint that invokes ListSpiffeEntries on the service.
// Primarily useful in a server.
func MakeListSpiffeEntriesEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListSpiffeEntriesRequest)
		response := svc.ListSpiffeEntries(ctx, req.Request)
		return ListSpiffeEntriesResponse{Response: response}, nil
	}
}

// MakeDeleteEntryEndpoint returns an endpoint that invokes DeleteEntry on the service.
// Primarily useful in a server.
func MakeDeleteEntryEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(DeleteEntryRequest)
		response := svc.DeleteEntry(ctx, req.Request)
		return DeleteEntryResponse{Response: response}, nil
	}
}
