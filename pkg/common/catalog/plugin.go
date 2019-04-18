package catalog

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
)

type CatalogPlugin struct {
	name         string
	log          logrus.FieldLogger
	plugin       interface{}
	all          []interface{}
	serviceNames []string

	closeOnce sync.Once
	closer    func()
}

func (p *CatalogPlugin) Name() string {
	return p.name
}

func (p *CatalogPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) error {
	type configurable interface {
		Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	}
	c, ok := p.plugin.(configurable)
	if !ok {
		return errs.New("plugin interface %T is not configurable", p.plugin)
	}
	_, err := c.Configure(ctx, req)
	if err != nil {
		return errs.Wrap(err)
	}
	return nil
}

func (p *CatalogPlugin) Fill(x interface{}) (err error) {
	cf := newPluginFiller(p)
	return cf.fill(x)
}

func (p *CatalogPlugin) Close() {
	p.closeOnce.Do(p.closer)
}
