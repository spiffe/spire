package catalog_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/sirupsen/logrus"
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
				config.PluginConfig["NodeAttestor"]["join_token"] = catalog.HCLPluginConfig{
					PluginCmd: filepath.Join(dir, "does-not-exist"),
				}
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "The built-in join_token node attestor cannot be overridden by an external plugin. The external plugin will be ignored; this will be a configuration error in a future release.",
				},
			},
		},
		{
			desc: "warn for deprecated node resolver",
			prepareConfig: func(dir string, config *catalog.Config) {
				config.PluginConfig["NodeResolver"]["azure_msi"] = catalog.HCLPluginConfig{}
			},
			// We don't actually care if the plugin successfully loads; just want to ensure we warn as expected.
			expectErr: "failed to configure plugin \"azure_msi\": rpc error: code = InvalidArgument desc = trust domain is missing",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "The node resolver plugin type is deprecated and will be removed from a future release",
				},
			},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			dir := t.TempDir()
			log, hook := test.NewNullLogger()

			config := catalog.Config{
				Log:           log,
				HealthChecker: fakeHealthChecker{},
				PluginConfig: catalog.HCLPluginConfigMap{
					"DataStore": {
						"sql": {
							PluginData: astPrintf(t, `
						database_type = "sqlite3"
						connection_string = %q
					`, filepath.Join(dir, "test.sql")),
						},
					},
					"KeyManager": {
						"memory": {},
					},
					"NodeAttestor": {
						"join_token": {},
					},
					"NodeResolver":      {},
					"Notifier":          {},
					"UpstreamAuthority": {},
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

func (fakeHealthChecker) AddCheck(name string, checkable health.Checkable) error { return nil }

func astPrintf(t *testing.T, format string, args ...interface{}) ast.Node {
	var n ast.Node
	err := hcl.Decode(&n, fmt.Sprintf(format, args...))
	require.NoError(t, err)
	return n
}
