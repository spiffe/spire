package spiretest

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/require"
)

type PluginOption interface {
	setOption(opts *pluginConfig)
}

type pluginOptionFunc func(opts *pluginConfig)

func (fn pluginOptionFunc) setOption(opts *pluginConfig) {
	fn(opts)
}

type pluginConfig struct {
	logger       logrus.FieldLogger
	hostServices []catalog.HostServiceServer
}

func Logger(logger logrus.FieldLogger) PluginOption {
	return pluginOptionFunc(func(config *pluginConfig) {
		config.logger = logger
	})
}

func HostService(hostService catalog.HostServiceServer) PluginOption {
	return pluginOptionFunc(func(config *pluginConfig) {
		config.hostServices = append(config.hostServices, hostService)
	})
}

func LoadPlugin(tb testing.TB, plugin catalog.Plugin, x interface{}, opts ...PluginOption) (done func()) {
	config := &pluginConfig{}
	for _, opt := range opts {
		opt.setOption(config)
	}

	p, err := catalog.LoadBuiltInPlugin(context.Background(), catalog.BuiltInPlugin{
		Log:          config.logger,
		Plugin:       plugin,
		HostServices: config.hostServices,
	})
	require.NoError(tb, err, "unable to load plugin")

	if err := p.Fill(x); err != nil {
		p.Close()
		require.NoError(tb, err, "unable to satisfy plugin client")
	}
	return p.Close
}
