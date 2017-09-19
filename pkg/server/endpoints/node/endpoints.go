package node

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	pb "github.com/spiffe/spire/proto/api/node"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	FetchBaseSVIDEndpoint        endpoint.Endpoint
	FetchSVIDEndpoint            endpoint.Endpoint
	FetchCPBundleEndpoint        endpoint.Endpoint
	FetchFederatedBundleEndpoint endpoint.Endpoint
}
type FetchBaseSVIDRequest struct {
	Request pb.FetchBaseSVIDRequest
}
type FetchBaseSVIDResponse struct {
	Response pb.FetchBaseSVIDResponse
}
type FetchSVIDRequest struct {
	Request pb.FetchSVIDRequest
}
type FetchSVIDResponse struct {
	Response pb.FetchSVIDResponse
}
type FetchCPBundleRequest struct {
	Request pb.FetchCPBundleRequest
}
type FetchCPBundleResponse struct {
	Response pb.FetchCPBundleResponse
}
type FetchFederatedBundleRequest struct {
	Request pb.FetchFederatedBundleRequest
}
type FetchFederatedBundleResponse struct {
	Response pb.FetchFederatedBundleResponse
}

func NewEndpoint(svc NodeService) (ep Endpoints) {
	ep.FetchBaseSVIDEndpoint = MakeFetchBaseSVIDEndpoint(svc)
	ep.FetchSVIDEndpoint = MakeFetchSVIDEndpoint(svc)
	ep.FetchCPBundleEndpoint = MakeFetchCPBundleEndpoint(svc)
	ep.FetchFederatedBundleEndpoint = MakeFetchFederatedBundleEndpoint(svc)
	return ep
}

// MakeFetchBaseSVIDEndpoint returns an endpoint that invokes FetchBaseSVID on the service.
// Primarily useful in a server.
func MakeFetchBaseSVIDEndpoint(svc NodeService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchBaseSVIDRequest)
		response, err := svc.FetchBaseSVID(ctx, req.Request)
		return FetchBaseSVIDResponse{Response: response}, err
	}
}

// MakeFetchSVIDEndpoint returns an endpoint that invokes FetchSVID on the service.
// Primarily useful in a server.
func MakeFetchSVIDEndpoint(svc NodeService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchSVIDRequest)
		response := svc.FetchSVID(ctx, req.Request)
		return FetchSVIDResponse{Response: response}, nil
	}
}

// MakeFetchCPBundleEndpoint returns an endpoint that invokes FetchCPBundle on the service.
// Primarily useful in a server.
func MakeFetchCPBundleEndpoint(svc NodeService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchCPBundleRequest)
		response := svc.FetchCPBundle(ctx, req.Request)
		return FetchCPBundleResponse{Response: response}, nil
	}
}

// MakeFetchFederatedBundleEndpoint returns an endpoint that invokes FetchFederatedBundle on the service.
// Primarily useful in a server.
func MakeFetchFederatedBundleEndpoint(svc NodeService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchFederatedBundleRequest)
		response := svc.FetchFederatedBundle(ctx, req.Request)
		return FetchFederatedBundleResponse{Response: response}, nil
	}
}
