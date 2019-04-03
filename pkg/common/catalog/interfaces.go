package catalog

import (
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/catalog/interfaces"
)

// The following interfaces are used by the generated code and need to be in
// another package so we don't get cyclic dependencies during unit-testing.
// They are aliased here for convenience.
type (
	PluginServer      = interfaces.PluginServer
	PluginClient      = interfaces.PluginClient
	ServiceServer     = interfaces.ServiceServer
	ServiceClient     = interfaces.ServiceClient
	HostServiceServer = interfaces.HostServiceServer
	HostServiceClient = interfaces.HostServiceClient
	HostServiceBroker = interfaces.HostServiceBroker
)

// NeedsLogger is implemented by plugin/service implementations that need a
// logger that is connected to the SPIRE core logger.
type NeedsLogger interface {
	SetLogger(hclog.Logger)
}

// NeedsHostBroker is implemented by plugin/service implementations that need
// to obtain clients to host services.
type NeedsHostServices interface {
	BrokerHostServices(HostServiceBroker) error
}
