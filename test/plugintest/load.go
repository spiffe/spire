package plugintest

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Loads a built-in plugin for testing with the given options. The plugin
// facade can be nil. If one of the Configure* options is given, the plugin
// will also be configured. The plugin will unload when the test is over. The
// returned closer may be called to unload the built-in before then, but can
// otherwise be ignored.
func Load(t *testing.T, builtIn catalog.BuiltIn, pluginFacade catalog.Facade, options ...Option) io.Closer {
	conf := &config{
		builtInConfig: catalog.BuiltInConfig{
			Log: nullLogger(),
		},
	}
	for _, opt := range options {
		opt.setOption(conf)
	}

	conn, err := catalog.LoadBuiltIn(context.Background(), builtIn, conf.builtInConfig)
	if conf.loadErr != nil {
		*conf.loadErr = err
		if err != nil {
			return nil
		}
	}
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })

	var facades []catalog.Facade
	if pluginFacade != nil {
		facades = append(facades, pluginFacade)
	}
	facades = append(facades, conf.serviceFacades...)

	configurer, err := conn.Bind(facades...)
	require.NoError(t, err)

	if conf.doConfigure {
		err := configurer.Configure(context.Background(), conf.coreConfig, conf.makeConfigData(t))
		if conf.configureErr != nil {
			*conf.configureErr = err
		} else {
			require.NoError(t, err)
		}
	}

	return conn
}

func nullLogger() logrus.FieldLogger {
	log, _ := test.NewNullLogger()
	return log
}
