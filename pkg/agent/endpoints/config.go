package endpoints

import (
	"crypto/x509"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/agent/catalog"

	tomb "gopkg.in/tomb.v2"
)

type Config struct {
	Bundle   []*x509.Certificate
	BindAddr *net.UnixAddr

	Catalog catalog.Catalog
	Manager cache.Manager

	Log logrus.FieldLogger
}

func New(c *Config) *endpoints {
	return &endpoints{
		c: c,
		t: new(tomb.Tomb),
	}
}
