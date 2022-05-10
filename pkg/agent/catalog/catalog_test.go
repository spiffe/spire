package catalog_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestJoinTokenNodeAttestorCannotBeOverriden(t *testing.T) {
	dir := t.TempDir()
	log, hook := test.NewNullLogger()

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
	require.NoError(t, err)
	spiretest.AssertLogsContainEntries(t, hook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.WarnLevel,
			Message: "The built-in join_token node attestor cannot be overridden by an external plugin. The external plugin will be ignored; this will be a configuration error in a future release.",
		},
	})
}
