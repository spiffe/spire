package server

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/spiffe/sri/control_plane/api/server/proto"
)

// Endpoints collects all of the endpoints that compose an add service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.

type Endpoints struct {
	StopEndpoint       endpoint.Endpoint
	PluginInfoEndpoint endpoint.Endpoint
}
type StopRequest struct {
	Request sri_proto.StopRequest
}
type StopResponse struct {
	Response sri_proto.StopReply
	Err      error
}
type PluginInfoRequest struct {
	Request sri_proto.PluginInfoRequest
}
type PluginInfoResponse struct {
	Response sri_proto.PluginInfoReply
	Err      error
}

func NewEndpoint(svc ServerService) (ep Endpoints) {
	ep.StopEndpoint = MakeStopEndpoint(svc)
	ep.PluginInfoEndpoint = MakePluginInfoEndpoint(svc)
	return ep
}

// MakeStopEndpoint returns an endpoint that invokes Stop on the service.
// Primarily useful in a server.
func MakeStopEndpoint(svc ServerService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(StopRequest)
		response, err := svc.Stop(ctx, req.Request)
		return StopResponse{Response: response, Err: err}, nil
	}
}

// MakePluginInfoEndpoint returns an endpoint that invokes PluginInfo on the service.
// Primarily useful in a server.
func MakePluginInfoEndpoint(svc ServerService) (ep endpoint.Endpoint) {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(PluginInfoRequest)
		response, err := svc.PluginInfo(ctx, req.Request)
		return PluginInfoResponse{Response: response, Err: err}, nil
	}
}
