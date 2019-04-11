package internal

import (
	"google.golang.org/grpc"
)

// PluginServer is the interface for both the primary interface and auxilliary
// services served by the plugin.
type PluginServer interface {
	// PluginType returns the plugin type
	PluginType() string

	// PluginClient returns the PluginClient interface for this server.
	PluginClient() PluginClient

	// Registers the implementation against the provided gRPC server and
	// retuns the implementation. The implementation is used to wire up
	// logging and host services.
	RegisterPluginServer(server *grpc.Server) interface{}
}

// PluginClient is used to initialize and return a plugin client.
type PluginClient interface {
	PluginType() string

	// NewPluginClient initializes and returns a service client.
	NewPluginClient(*grpc.ClientConn) interface{}
}

// ServiceServer is the interface for both the primary interface and auxilliary
// services served by the plugin.
type ServiceServer interface {
	// ServiceType returns the service type
	ServiceType() string

	// ServiceClient returns the PluginClient interface for this server.
	ServiceClient() ServiceClient

	// Registers the implementation against the provided gRPC server and
	// retuns the implementation. The implementation is used to wire up
	// logging and host services.
	RegisterServiceServer(server *grpc.Server) interface{}
}

// ServiceClient is used to initialize and return a service client.
type ServiceClient interface {
	// ServiceType returns the service type
	ServiceType() string

	// NewServiceClient initializes and returns a service client.
	NewServiceClient(*grpc.ClientConn) interface{}
}

// HostServiceServer is used to register a host service server.
type HostServiceServer interface {
	// HostServiceType returns the host service type
	HostServiceType() string

	// RegisterHostServiceServer registers the host service server.
	RegisterHostServiceServer(*grpc.Server)
}

// HostServiceClient is used to initialize a host service client.
type HostServiceClient interface {
	HostServiceType() string

	// InitHostServiceClient initializes the host service client.
	InitHostServiceClient(conn *grpc.ClientConn)
}

// HostServiceBroker is used by plugins that implement the NeedsHostBroker
// service to obtain host service clients.
type HostServiceBroker interface {
	GetHostService(HostServiceClient) (has bool, err error)
}
