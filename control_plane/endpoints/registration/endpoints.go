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
	CreateEntryEndpoint           endpoint.Endpoint
	DeleteEntryEndpoint           endpoint.Endpoint
	ListByAttestorEndpoint        endpoint.Endpoint
	ListBySelectorEndpoint        endpoint.Endpoint
	ListBySpiffeIDEndpoint        endpoint.Endpoint
	CreateFederatedBundleEndpoint endpoint.Endpoint
	ListFederatedBundlesEndpoint  endpoint.Endpoint
	UpdateFederatedBundleEndpoint endpoint.Endpoint
	DeleteFederatedBundleEndpoint endpoint.Endpoint
}
type CreateEntryRequest struct {
	Request pb.CreateEntryRequest
}
type CreateEntryResponse struct {
	Response pb.CreateEntryResponse
}
type DeleteEntryRequest struct {
	Request pb.DeleteEntryRequest
}
type DeleteEntryResponse struct {
	Response pb.DeleteEntryResponse
}
type ListByAttestorRequest struct {
	Request pb.ListByAttestorRequest
}
type ListByAttestorResponse struct {
	Response pb.ListByAttestorResponse
}
type ListBySelectorRequest struct {
	Request pb.ListBySelectorRequest
}
type ListBySelectorResponse struct {
	Response pb.ListBySelectorResponse
}
type ListBySpiffeIDRequest struct {
	Request pb.ListBySpiffeIDRequest
}
type ListBySpiffeIDResponse struct {
	Response pb.ListBySpiffeIDResponse
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

func NewEndpoint(svc RegistrationService) (ep Endpoints) {
	ep.CreateEntryEndpoint = MakeCreateEntryEndpoint(svc)
	ep.DeleteEntryEndpoint = MakeDeleteEntryEndpoint(svc)
	ep.ListByAttestorEndpoint = MakeListByAttestorEndpoint(svc)
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
		response := svc.CreateEntry(ctx, req.Request)
		return CreateEntryResponse{Response: response}, nil
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

// MakeListByAttestorEndpoint returns an endpoint that invokes ListByAttestor on the service.
// Primarily useful in a server.
func MakeListByAttestorEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListByAttestorRequest)
		response := svc.ListByAttestor(ctx, req.Request)
		return ListByAttestorResponse{Response: response}, nil
	}
}

// MakeListBySelectorEndpoint returns an endpoint that invokes ListBySelector on the service.
// Primarily useful in a server.
func MakeListBySelectorEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListBySelectorRequest)
		response := svc.ListBySelector(ctx, req.Request)
		return ListBySelectorResponse{Response: response}, nil
	}
}

// MakeListBySpiffeIDEndpoint returns an endpoint that invokes ListBySpiffeID on the service.
// Primarily useful in a server.
func MakeListBySpiffeIDEndpoint(svc RegistrationService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ListBySpiffeIDRequest)
		response := svc.ListBySpiffeID(ctx, req.Request)
		return ListBySpiffeIDResponse{Response: response}, nil
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
