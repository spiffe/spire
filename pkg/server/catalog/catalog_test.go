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

func TestJoinTokenNodeAttestorCannotBeOverriden(t *testing.T) {
	dir := t.TempDir()
	log, hook := test.NewNullLogger()

	minimalConfig := func() catalog.Config {
		return catalog.Config{
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

type fakeHealthChecker struct{}

func (fakeHealthChecker) AddCheck(name string, checkable health.Checkable) error { return nil }

func astPrintf(t *testing.T, format string, args ...interface{}) ast.Node {
	var n ast.Node
	err := hcl.Decode(&n, fmt.Sprintf(format, args...))
	require.NoError(t, err)
	return n
}
