package plugintest

import (
	"encoding/json"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/require"
)

type config struct {
	builtInConfig catalog.BuiltInConfig

	serviceFacades []catalog.Facade

	loadErr *error

	doConfigure  bool
	configureErr *error
	coreConfig   catalog.CoreConfig
	plainConfig  *string
	jsonConfig   any
}

func (conf *config) makeConfigData(t *testing.T) string {
	var configData string
	switch {
	case conf.plainConfig != nil && conf.jsonConfig != nil:
		t.Fatal("cannot set both plain and JSON config")
	case conf.jsonConfig != nil:
		jsonBytes, err := json.Marshal(conf.jsonConfig)
		require.NoError(t, err, "unable to marshal JSON config")
		configData = string(jsonBytes)
	case conf.plainConfig != nil:
		configData = *conf.plainConfig
	}
	return configData
}
