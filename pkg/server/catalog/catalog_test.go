package catalog_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	for _, tt := range []struct {
		desc          string
		prepareConfig func(dir string, config *catalog.Config)
		expectErr     string
		expectLogs    []spiretest.LogEntry
	}{
		{
			desc: "join_token node attestor cannot be overridden",
			prepareConfig: func(dir string, config *catalog.Config) {
				for i, pluginConfig := range config.PluginConfigs {
					if pluginConfig.Type == "NodeAttestor" && pluginConfig.Name == "join_token" {
						config.PluginConfigs[i].Path = filepath.Join(dir, "does-not-exist")
					}
				}
			},
			expectErr: "the built-in join_token node attestor cannot be overridden by an external plugin",
		},
		{
			desc: "datastore cannot be overridden",
			prepareConfig: func(dir string, config *catalog.Config) {
				for i, pluginConfig := range config.PluginConfigs {
					if pluginConfig.Type == "DataStore" {
						config.PluginConfigs[i].Path = filepath.Join(dir, "does-not-exist")
					}
				}
			},
			expectErr: `pluggability for the DataStore is deprecated; only the built-in "sql" plugin is supported`,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			dir := t.TempDir()
			log, hook := test.NewNullLogger()

			config := catalog.Config{
				Log:           log,
				HealthChecker: fakeHealthChecker{},
				PluginConfigs: catalog.PluginConfigs{
					{
						Type: "DataStore",
						Name: "sql",
						Data: fmt.Sprintf(`
						database_type = "sqlite3"
						connection_string = %q
					`, filepath.Join(dir, "test.sql")),
					},
					{
						Type: "KeyManager",
						Name: "memory",
					},
					{
						Type: "NodeAttestor",
						Name: "join_token",
					},
				},
			}
			if tt.prepareConfig != nil {
				tt.prepareConfig(dir, &config)
			}
			repo, err := catalog.Load(context.Background(), config)
			if repo != nil {
				repo.Close()
			}
			spiretest.AssertLogsContainEntries(t, hook.AllEntries(), tt.expectLogs)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

type fakeHealthChecker struct{}

func (fakeHealthChecker) AddCheck(string, health.Checkable) error { return nil }
