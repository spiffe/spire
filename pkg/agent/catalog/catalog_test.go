package catalog_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/stretchr/testify/require"
)

func TestJoinTokenNodeAttestorCannotBeOverriden(t *testing.T) {
	dir := t.TempDir()
	log, _ := test.NewNullLogger()

	minimalConfig := func() catalog.Config {
		return catalog.Config{
			Log: log,
			PluginConfig: catalog.HCLPluginConfigMap{
				"KeyManager": {
					"memory": {},
				},
				"NodeAttestor": {
					"join_token": {},
				},
				"WorkloadAttestor": {
					"docker": {},
				},
			},
		}
	}

	config := minimalConfig()
	config.PluginConfig["NodeAttestor"]["join_token"] = catalog.HCLPluginConfig{
		PluginCmd: filepath.Join(dir, "does-not-exist"),
	}

	repo, err := catalog.Load(context.Background(), config)
	if repo != nil {
		repo.Close()
	}
	require.EqualError(t, err, "the built-in join_token node attestor cannot be overridden by an external plugin")
}
