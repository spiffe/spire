//go:build !windows

package validate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/stretchr/testify/require"
)

func serverConfigWithPlugins(pluginConfig string) string {
	return `
server {
	trust_domain = "example.org"
  data_dir = "/opt/spire/server/data"
}

plugins {
` + pluginConfig + `
}
`
}

func TestValidateConfig(t *testing.T) {
	configDir := t.TempDir()

	testCases := []struct {
		name                   string
		config                 string
		expectedReturn         int
		expectedErrors         []string
		expectedStderr         string
		pluginDataFilePath     string
		pluginDataFileContents string
	}{
		{
			name:           "empty config",
			config:         serverConfigWithPlugins(""),
			expectedReturn: 1,
			expectedErrors: []string{
				"'datastore' must be configured",
				"KeyManager:\n\t\tconstraint not satisfied: expected exactly 1 but got 0\n",
			},
		},
		{
			name: "valid config",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

UpstreamAuthority "disk" {
	plugin_data = {
		cert_file_path = "some/file/some/where"
		key_file_path = "some/file/some/where/else"
	}
}
`),
			expectedReturn: 0,
			expectedStderr: "",
		},
		{
			name: "unknown plugin",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

UpstreamAuthority "thisdoesnotexist" {
	plugin_data = {}
}
`),
			expectedReturn: 1,
			expectedStderr: "Could not validate configuration file: failed to load plugin \"thisdoesnotexist\": no built-in plugin \"thisdoesnotexist\" for type \"UpstreamAuthority\"",
		},
		{
			name: "plugin with bad configuration",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

UpstreamAuthority "disk" {
	plugin_data = {
		cert_file_path = "some/file/some/where"
	}
}
`),
			expectedReturn: 1,
			expectedErrors: []string{
				"UpstreamAuthority \"disk\":\n\t\t'cert_file_path' and 'key_file_path' must be set and not empty\n",
			},
		},
		{
			name: "multiple plugins with bad configuration",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

NodeAttestor "x509pop" {
	plugin_data = {
	}
}

UpstreamAuthority "disk" {
	plugin_data = {
		cert_file_path = "some/file/some/where"
	}
}
`),
			expectedReturn: 1,
			expectedErrors: []string{
				"NodeAttestor \"x509pop\":\n\t\tone of ca_bundle_path or ca_bundle_paths must be configured\n",
				"UpstreamAuthority \"disk\":\n\t\t'cert_file_path' and 'key_file_path' must be set and not empty\n",
			},
		},
		{
			name: "missing plugin_data_file",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

UpstreamAuthority "disk" {
	plugin_data_file = "this/does/not/exist"
}
`),
			expectedReturn: 1,
			expectedErrors: []string{
				"UpstreamAuthority \"disk\":\n\t\tfailed to read plugin configuration: open this/does/not/exist: no such file or directory",
			},
		},
		{
			name: "invalid data in plugin_data_file",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

UpstreamAuthority "disk" {
	plugin_data_file = "PLUGIN_DATA_FILE_LOCATION"
}
`),
			expectedReturn:     1,
			pluginDataFilePath: filepath.Join(configDir, "plugin_data_file_bad"),
			pluginDataFileContents: `
cert_file_path = "some/file/some/where"
`,
			expectedErrors: []string{
				"UpstreamAuthority \"disk\":\n\t\t'cert_file_path' and 'key_file_path' must be set and not empty\n",
			},
		},
		{
			name: "missing plugin_config",
			config: serverConfigWithPlugins(`
DataStore "sql" {
    plugin_data {
        database_type = "sqlite3"
        connection_string = "/some/path/to/the/datastore.sqlite3"
    }
}
KeyManager "memory" {
    plugin_data = {}
}

UpstreamAuthority "disk" {}
`),
			expectedReturn: 1,
			expectedErrors: []string{
				"UpstreamAuthority \"disk\":\n\t\t'cert_file_path' and 'key_file_path' must be set and not empty\n",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_ = fflag.Unload()
			stdin := new(bytes.Buffer)
			stdout := new(bytes.Buffer)
			stderr := new(bytes.Buffer)

			cmd := newValidateCommand(&common_cli.Env{
				Stdin:  stdin,
				Stdout: stdout,
				Stderr: stderr,
			})

			config := testCase.config
			if testCase.pluginDataFilePath != "" {
				config = strings.ReplaceAll(testCase.config, "PLUGIN_DATA_FILE_LOCATION", testCase.pluginDataFilePath)
			}

			serverConfPath := filepath.Join(configDir, "server.conf")
			err := os.WriteFile(serverConfPath, []byte(config), 0600)
			require.NoError(t, err)

			if testCase.pluginDataFilePath != "" {
				err = os.WriteFile(testCase.pluginDataFilePath, []byte(testCase.pluginDataFileContents), 0600)
				require.NoError(t, err)
			}

			rcode := cmd.Run([]string{
				"-config",
				serverConfPath,
			})

			require.Equal(t, testCase.expectedReturn, rcode)
			for _, error := range testCase.expectedErrors {
				require.Contains(t, stderr.String(), error)
			}
			if testCase.expectedStderr != "" {
				require.Equal(t, testCase.expectedStderr, stderr.String())
			}
		})
	}
}
