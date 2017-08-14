package workload

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/spiffe/sri/node_agent/api/workload/pb"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	FetchSVIDBundleEndpoint       endpoint.Endpoint
	FetchSVIDBundlesEndpoint      endpoint.Endpoint
	FetchFederatedBundleEndpoint  endpoint.Endpoint
	FetchFederatedBundlesEndpoint endpoint.Endpoint
}
type FetchSVIDBundleRequest struct {
	Request pb.FetchSVIDBundleRequest
}
type FetchSVIDBundleResponse struct {
	Response pb.FetchSVIDBundleResponse
}
type FetchSVIDBundlesRequest struct {
	Request pb.Empty
}
type FetchSVIDBundlesResponse struct {
	Response pb.FetchSVIDBundlesResponse
}
type FetchFederatedBundleRequest struct {
	Request pb.FetchFederatedBundleRequest
}
type FetchFederatedBundleResponse struct {
	Response pb.FetchFederatedBundleResponse
}
type FetchFederatedBundlesRequest struct {
	Request pb.Empty
}
type FetchFederatedBundlesResponse struct {
	Response pb.FetchFederatedBundlesResponse
}

func NewEndpoint(svc WorkloadService) (ep Endpoints) {
	ep.FetchSVIDBundleEndpoint = MakeFetchSVIDBundleEndpoint(svc)
	ep.FetchSVIDBundlesEndpoint = MakeFetchSVIDBundlesEndpoint(svc)
	ep.FetchFederatedBundleEndpoint = MakeFetchFederatedBundleEndpoint(svc)
	ep.FetchFederatedBundlesEndpoint = MakeFetchFederatedBundlesEndpoint(svc)
	return ep
}

// MakeFetchSVIDBundleEndpoint returns an endpoint that invokes FetchSVIDBundle on the service.
// Primarily useful in a server.
func MakeFetchSVIDBundleEndpoint(svc WorkloadService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchSVIDBundleRequest)
		response := svc.FetchSVIDBundle(ctx, req.Request)
		return FetchSVIDBundleResponse{Response: response}, nil
	}
}

// MakeFetchSVIDBundlesEndpoint returns an endpoint that invokes FetchSVIDBundles on the service.
// Primarily useful in a server.
func MakeFetchSVIDBundlesEndpoint(svc WorkloadService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchSVIDBundlesRequest)
		response := svc.FetchSVIDBundles(ctx, req.Request)
		return FetchSVIDBundlesResponse{Response: response}, nil
	}
}

// MakeFetchFederatedBundleEndpoint returns an endpoint that invokes FetchFederatedBundle on the service.
// Primarily useful in a server.
func MakeFetchFederatedBundleEndpoint(svc WorkloadService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchFederatedBundleRequest)
		response := svc.FetchFederatedBundle(ctx, req.Request)
		return FetchFederatedBundleResponse{Response: response}, nil
	}
}

// MakeFetchFederatedBundlesEndpoint returns an endpoint that invokes FetchFederatedBundles on the service.
// Primarily useful in a server.
func MakeFetchFederatedBundlesEndpoint(svc WorkloadService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchFederatedBundlesRequest)
		response := svc.FetchFederatedBundles(ctx, req.Request)
		return FetchFederatedBundlesResponse{Response: response}, nil
	}
}
