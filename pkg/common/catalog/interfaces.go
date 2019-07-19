package catalog

import (
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/catalog/internal"
)

// The following interfaces are used by the generated code and need to be in
// another package so we don't get cyclic dependencies during unit-testing.
// They are aliased here for convenience.
type (
	PluginServer      = internal.PluginServer
	PluginClient      = internal.PluginClient
	ServiceServer     = internal.ServiceServer
	ServiceClient     = internal.ServiceClient
	HostServiceServer = internal.HostServiceServer
	HostServiceClient = internal.HostServiceClient
	HostServiceBroker = internal.HostServiceBroker
)

// NeedsLogger is implemented by plugin/service implementations that need a
// logger that is connected to the SPIRE core logger.
type NeedsLogger interface {
	SetLogger(hclog.Logger)
}

// NeedsHostServices is implemented by plugin/service implementations that need
// to obtain clients to host services.
type NeedsHostServices interface {
	BrokerHostServices(HostServiceBroker) error
}
