package endpoints

import (
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"

	"google.golang.org/grpc"

	"gopkg.in/tomb.v2"
)

type Config struct {
	// Addresses to bind the servers to
	GRPCAddr *net.TCPAddr
	HTTPAddr *net.TCPAddr

	// A hook allowing the consumer to customize the gRPC server before it starts.
	GRPCHook func(*grpc.Server) error

	// The server's configured trust domain. Used for validation, server SVID, etc.
	TrustDomain url.URL

	// Plugin catalog for retreiving signing certs and generating server SVIDs
	Catalog catalog.Catalog

	Log logrus.FieldLogger
}

func New(c *Config) *endpoints {
	return &endpoints{
		c:         c,
		mtx:       new(sync.RWMutex),
		t:         new(tomb.Tomb),
		svidCheck: time.NewTicker(30 * time.Second),
		runOnce:   new(sync.Once),
	}
}
