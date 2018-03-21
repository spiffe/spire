package endpoints

import (
	"crypto/x509"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/common/telemetry"

	tomb "gopkg.in/tomb.v2"
)

type Config struct {
	Bundle   []*x509.Certificate
	BindAddr *net.UnixAddr

	Catalog catalog.Catalog
	Manager manager.Manager

	Log logrus.FieldLogger
	Tel telemetry.Sink
}

func New(c *Config) *endpoints {
	return &endpoints{
		c: c,
		t: new(tomb.Tomb),
	}
}
