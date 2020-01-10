package endpoints

import (
	"net"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/endpoints/bundle"
	"github.com/spiffe/spire/pkg/server/svid"

	"google.golang.org/grpc"
)

// Config is a configuration for endpoints
type Config struct {
	// Addresses to bind the servers to
	TCPAddr *net.TCPAddr
	UDSAddr *net.UnixAddr

	// A hook allowing the consumer to customize the gRPC server before it starts.
	GRPCHook func(*grpc.Server) error

	// The svid rotator used to obtain the latest server credentials
	SVIDObserver svid.Observer

	// The server's configured trust domain. Used for validation, server SVID, etc.
	TrustDomain url.URL

	// Plugin catalog
	Catalog catalog.Catalog

	// Server CA for signing SVIDs
	ServerCA ca.ServerCA

	// Allow agentless spiffeIds when doing node attestation
	AllowAgentlessNodeAttestors bool

	// Bundle endpoint address
	BundleEndpointAddress *net.TCPAddr

	// Bundle endpoint ACME configuration. If unset, SPIFFE auth will be used.
	BundleEndpointACME *bundle.ACMEConfig

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics
}

// New creates new endpoints struct
func New(c *Config) *Endpoints {
	return &Endpoints{
		c:   c,
		mtx: new(sync.RWMutex),
		unixListener: &peertracker.ListenerFactory{
			Log: c.Log,
		},
	}
}
