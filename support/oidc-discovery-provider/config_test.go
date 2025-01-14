package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

type parseConfigCase struct {
	name string
	in   string
	out  *Config
	err  string
}

func TestLoadConfig(t *testing.T) {
	require := require.New(t)

	dir := spiretest.TempDir(t)

	confPath := filepath.Join(dir, "test.conf")

	_, err := LoadConfig(confPath, false)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = os.WriteFile(confPath, []byte(minimalEnvServerAPIConfig), 0o600)
	require.NoError(err)

	os.Setenv("SPIFFE_TRUST_DOMAIN", "domain.test")
	config, err := LoadConfig(confPath, true)
	require.NoError(err)

	require.Equal(&Config{
		LogLevel: defaultLogLevel,
		Domains:  []string{"domain.test"},
		ACME: &ACMEConfig{
			CacheDir:    defaultCacheDir,
			Email:       "admin@domain.test",
			ToSAccepted: true,
		},
		ServerAPI: serverAPIConfig,
	}, config)

	err = os.WriteFile(confPath, []byte(minimalServerAPIConfig), 0o600)
	require.NoError(err)

	config, err = LoadConfig(confPath, false)
	require.NoError(err)

	require.Equal(&Config{
		LogLevel: defaultLogLevel,
		Domains:  []string{"domain.test"},
		ACME: &ACMEConfig{
			CacheDir:    defaultCacheDir,
			Email:       "admin@domain.test",
			ToSAccepted: true,
		},
		ServerAPI: serverAPIConfig,
	}, config)
}

func TestParseConfig(t *testing.T) {
	testCases := []parseConfigCase{
		{
			name: "malformed HCL",
			in:   `BAD`,
			err:  "unable to decode configuration",
		},
		{
			name: "no source section configured",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
			`,
			err: "either the server_api or workload_api section must be configured",
		},
	}
	testCases = append(testCases, parseConfigCasesOS()...)

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := ParseConfig(testCase.in)
			if testCase.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.out, actual)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
