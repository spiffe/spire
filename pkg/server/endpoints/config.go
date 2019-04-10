package endpoints

import (
	"net"
	"net/url"
	"sync"

	observer "github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"

	"google.golang.org/grpc"
)

type Config struct {
	// Addresses to bind the servers to
	TCPAddr *net.TCPAddr
	UDSAddr *net.UnixAddr

	// A hook allowing the consumer to customize the gRPC server before it starts.
	GRPCHook func(*grpc.Server) error

	// A subscription to the SVID stream
	SVIDStream observer.Stream

	// The server's configured trust domain. Used for validation, server SVID, etc.
	TrustDomain url.URL

	// Plugin catalog
	Catalog catalog.Catalog

	// Server CA for signing SVIDs
	ServerCA ca.ServerCA

	// Allow agentless spiffeIds when doing node attestation
	AllowAgentlessNodeAttestors bool

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics
}

func New(c *Config) *endpoints {
	return &endpoints{
		c:   c,
		mtx: new(sync.RWMutex),
	}
}
