package ca

import (
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/catalog"

	tomb "gopkg.in/tomb.v2"
)

type Config struct {
	Catalog     catalog.Catalog
	TrustDomain url.URL

	Log logrus.FieldLogger
}

func New(c *Config) *manager {
	return &manager{
		c:   c,
		t:   new(tomb.Tomb),
		mtx: new(sync.RWMutex),

		pruneTicker: time.NewTicker(6 * time.Hour),
	}
}
