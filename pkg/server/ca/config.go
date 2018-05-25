package ca

import (
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"
)

type Config struct {
	Catalog     catalog.Catalog
	TrustDomain url.URL

	UpstreamBundle bool

	Log logrus.FieldLogger
}

func New(c *Config) Manager {
	return &manager{
		c:   c,
		mtx: new(sync.RWMutex),
	}
}
