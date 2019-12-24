package catalog

import (
	"context"
	"sync"

	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
)

type LoadedPlugin struct {
	name         string
	plugin       interface{}
	all          []interface{}
	serviceNames []string

	closeOnce sync.Once
	closer    func()
}

func (p *LoadedPlugin) Name() string {
	return p.name
}

func (p *LoadedPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) error {
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

func (p *LoadedPlugin) Fill(x interface{}) (err error) {
	cf := newPluginFiller(p)
	return cf.fill(x)
}

func (p *LoadedPlugin) Close() {
	p.closeOnce.Do(p.closer)
}
