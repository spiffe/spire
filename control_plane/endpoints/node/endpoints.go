package node

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/spiffe/control-plane/api/node/pb"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	FetchBootstrapSVIDEndpoint endpoint.Endpoint
	FetchNodeSVIDEndpoint      endpoint.Endpoint
	FetchSVIDEndpoint          endpoint.Endpoint
	FetchCPBundleEndpoint      endpoint.Endpoint
}
type FetchBootstrapSVIDRequest struct {
	Request pb.FetchBootstrapSVIDRequest
}
type FetchBootstrapSVIDResponse struct {
	Response pb.FetchBootstrapSVIDResponse
}
type FetchNodeSVIDRequest struct {
	Request pb.FetchNodeSVIDRequest
}
type FetchNodeSVIDResponse struct {
	Response pb.FetchBootstrapSVIDResponse
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

func NewEndpoint(svc NodeService) (ep Endpoints) {
	ep.FetchBootstrapSVIDEndpoint = MakeFetchBootstrapSVIDEndpoint(svc)
	ep.FetchNodeSVIDEndpoint = MakeFetchNodeSVIDEndpoint(svc)
	ep.FetchSVIDEndpoint = MakeFetchSVIDEndpoint(svc)
	ep.FetchCPBundleEndpoint = MakeFetchCPBundleEndpoint(svc)
	return ep
}

// MakeFetchBootstrapSVIDEndpoint returns an endpoint that invokes FetchBootstrapSVID on the service.
// Primarily useful in a server.
func MakeFetchBootstrapSVIDEndpoint(svc NodeService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchBootstrapSVIDRequest)
		response := svc.FetchBootstrapSVID(ctx, req.Request)
		return FetchBootstrapSVIDResponse{Response: response}, nil
	}
}

// MakeFetchNodeSVIDEndpoint returns an endpoint that invokes FetchNodeSVID on the service.
// Primarily useful in a server.
func MakeFetchNodeSVIDEndpoint(svc NodeService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchNodeSVIDRequest)
		response := svc.FetchNodeSVID(ctx, req.Request)
		return FetchNodeSVIDResponse{Response: response}, nil
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
