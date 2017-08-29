package workload

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	pb "github.com/spiffe/sri/pkg/api/workload"
	"github.com/spiffe/sri/pkg/common"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	FetchBundlesEndpoint    endpoint.Endpoint
	FetchAllBundlesEndpoint endpoint.Endpoint
}
type FetchBundlesRequest struct {
	Request pb.SpiffeId
}
type FetchBundlesResponse struct {
	Response pb.Bundles
}
type FetchAllBundlesRequest struct {
	Request common.Empty
}
type FetchAllBundlesResponse struct {
	Response pb.Bundles
}

func NewEndpoint(svc Service) (ep Endpoints) {
	ep.FetchBundlesEndpoint = MakeFetchBundlesEndpoint(svc)
	ep.FetchAllBundlesEndpoint = MakeFetchAllBundlesEndpoint(svc)
	return ep
}

// MakeFetchBundlesEndpoint returns an endpoint that invokes FetchSVIDBundle on the service.
// Primarily useful in a server.
func MakeFetchBundlesEndpoint(svc Service) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchBundlesRequest)
		response, err := svc.FetchBundles(ctx, req.Request)
		return FetchAllBundlesResponse{Response: response}, err
	}
}

// MakeFetchAllBundlesEndpoint returns an endpoint that invokes FetchSVIDBundles on the service.
// Primarily useful in a server.
func MakeFetchAllBundlesEndpoint(svc Service) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchAllBundlesRequest)
		response, err := svc.FetchAllBundles(ctx, req.Request)
		return FetchBundlesResponse{Response: response}, err
	}
}
