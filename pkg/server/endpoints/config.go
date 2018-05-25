package endpoints

import (
	"net"
	"net/url"
	"sync"

	"github.com/imkira/go-observer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"

	"google.golang.org/grpc"
)

type Config struct {
	// Addresses to bind the servers to
	GRPCAddr *net.TCPAddr
	HTTPAddr *net.TCPAddr

	// A hook allowing the consumer to customize the gRPC server before it starts.
	GRPCHook func(*grpc.Server) error

	// A subscription to the SVID stream
	SVIDStream observer.Stream

	// The server's configured trust domain. Used for validation, server SVID, etc.
	TrustDomain url.URL

	// Plugin catalog for retreiving signing certs and generating server SVIDs
	Catalog catalog.Catalog

	Log logrus.FieldLogger
}

func New(c *Config) *endpoints {
	return &endpoints{
		c:   c,
		mtx: new(sync.RWMutex),
	}
}
