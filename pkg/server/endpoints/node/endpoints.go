package node

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	pb "github.com/spiffe/spire/pkg/api/node"
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

func NewEndpoint(svc Service) (ep Endpoints) {
	ep.FetchBaseSVIDEndpoint = MakeFetchBaseSVIDEndpoint(svc)
	ep.FetchSVIDEndpoint = MakeFetchSVIDEndpoint(svc)
	ep.FetchCPBundleEndpoint = MakeFetchCPBundleEndpoint(svc)
	ep.FetchFederatedBundleEndpoint = MakeFetchFederatedBundleEndpoint(svc)
	return ep
}

// MakeFetchBaseSVIDEndpoint returns an endpoint that invokes FetchBaseSVID on the service.
// Primarily useful in a server.
func MakeFetchBaseSVIDEndpoint(svc Service) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchBaseSVIDRequest)
		response, err := svc.FetchBaseSVID(ctx, req.Request)
		return FetchBaseSVIDResponse{Response: response}, err
	}
}

// MakeFetchSVIDEndpoint returns an endpoint that invokes FetchSVID on the service.
// Primarily useful in a server.
func MakeFetchSVIDEndpoint(svc Service) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchSVIDRequest)
		response, err := svc.FetchSVID(ctx, req.Request)
		return FetchSVIDResponse{Response: response}, err
	}
}

// MakeFetchCPBundleEndpoint returns an endpoint that invokes FetchCPBundle on the service.
// Primarily useful in a server.
func MakeFetchCPBundleEndpoint(svc Service) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchCPBundleRequest)
		response, err := svc.FetchCPBundle(ctx, req.Request)
		return FetchCPBundleResponse{Response: response}, err
	}
}

// MakeFetchFederatedBundleEndpoint returns an endpoint that invokes FetchFederatedBundle on the service.
// Primarily useful in a server.
func MakeFetchFederatedBundleEndpoint(svc Service) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchFederatedBundleRequest)
		response, err := svc.FetchFederatedBundle(ctx, req.Request)
		return FetchFederatedBundleResponse{Response: response}, err
	}
}
