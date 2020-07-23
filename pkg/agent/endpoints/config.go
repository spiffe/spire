package endpoints

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"

	"google.golang.org/grpc"
)

type Config struct {
	BindAddr *net.UnixAddr

	GRPCHook func(*grpc.Server) error

	Catalog catalog.Catalog
	Manager manager.Manager

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	// The TLS Certificate resource name to use for the default X509-SVID with Envoy SDS
	DefaultSVIDName string

	// The Validation Context resource name to use for the default X.509 bundle with Envoy SDS
	DefaultBundleName string
}

func New(c *Config) *Endpoints {
	return &Endpoints{
		c: c,
		unixListener: &peertracker.ListenerFactory{
			Log: c.Log,
		},
	}
}
