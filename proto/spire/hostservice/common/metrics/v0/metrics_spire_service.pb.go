// Code generated by protoc-gen-go-spire. DO NOT EDIT.

package metricsv0

import (
	pluginsdk "github.com/spiffe/spire-plugin-sdk/pluginsdk"
	grpc "google.golang.org/grpc"
)

func MetricsServiceServiceServer(server MetricsServiceServer) pluginsdk.ServiceServer {
	return metricsServiceServiceServer{MetricsServiceServer: server}
}

type metricsServiceServiceServer struct {
	MetricsServiceServer
}

func (s metricsServiceServiceServer) GRPCServiceName() string {
	return "spire.common.hostservices.MetricsService"
}

func (s metricsServiceServiceServer) RegisterServer(server *grpc.Server) interface{} {
	RegisterMetricsServiceServer(server, s.MetricsServiceServer)
	return s.MetricsServiceServer
}

type MetricsServiceServiceClient struct {
	MetricsServiceClient
}

func (c *MetricsServiceServiceClient) IsInitialized() bool {
	return c.MetricsServiceClient != nil
}

func (c *MetricsServiceServiceClient) GRPCServiceName() string {
	return "spire.common.hostservices.MetricsService"
}

func (c *MetricsServiceServiceClient) InitClient(conn grpc.ClientConnInterface) interface{} {
	c.MetricsServiceClient = NewMetricsServiceClient(conn)
	return c.MetricsServiceClient
}
