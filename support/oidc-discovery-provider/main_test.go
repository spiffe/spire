package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMain_UnexpectedArguments(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantExit int
		wantErr  string
	}{
		{
			name:     "no unexpected arguments",
			args:     []string{},
			wantExit: 0,
		},
		{
			name:     "single unexpected argument",
			args:     []string{"unexpected"},
			wantExit: 1,
			wantErr:  "Error: unexpected arguments: [unexpected]",
		},
		{
			name:     "unexpected arguments with flag",
			args:     []string{"-config", "test.conf", "unexpected"},
			wantExit: 1,
			wantErr:  "Error: unexpected arguments: [unexpected]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We need to test this by running the actual binary since main() calls os.Exit()
			// This is a common pattern for testing CLI applications in Go
			if os.Getenv("BE_CRASHER") == "1" {
				// Reset flags for each test
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
				versionFlag = flag.Bool("version", false, "print version")
				configFlag = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
				expandEnv = flag.Bool("expandEnv", false, "expand environment variables in config file")

				// Set up args
				os.Args = append([]string{"oidc-discovery-provider"}, tt.args...)
				main()
				return
			}

			// Run the test in a subprocess
			// #nosec G204 - os.Args[0] is safe in test context
			cmd := exec.Command(os.Args[0], "-test.run=TestMain_UnexpectedArguments/"+tt.name)
			cmd.Env = append(os.Environ(), "BE_CRASHER=1")

			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()

			if tt.wantExit == 0 {
				// For successful cases, we expect the process to fail because LoadConfig will fail
				// but we shouldn't see the "unexpected arguments" error
				require.NotContains(t, stderr.String(), "Error: unexpected arguments:")
			} else {
				// For error cases, we expect the process to exit with error
				require.Error(t, err)
				require.Contains(t, stderr.String(), tt.wantErr)

				// Verify usage information is printed
				require.Contains(t, stderr.String(), "Usage of")
				require.Contains(t, stderr.String(), "-config string")
				require.Contains(t, stderr.String(), "-expandEnv")
				require.Contains(t, stderr.String(), "-version")
			}
		})
	}
}

func TestMain_VersionFlag(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		// Reset flags
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		versionFlag = flag.Bool("version", false, "print version")
		configFlag = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
		expandEnv = flag.Bool("expandEnv", false, "expand environment variables in config file")

		os.Args = []string{"oidc-discovery-provider", "-version"}
		main()
		return
	}

	// #nosec G204 - os.Args[0] is safe in test context
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_VersionFlag")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()

	// Version flag should cause clean exit (exit code 0)
	require.NoError(t, err)

	// Should print version information
	output := stdout.String()
	require.NotEmpty(t, strings.TrimSpace(output))
}

func TestMain_UsageOutput(t *testing.T) {
	// Test that the usage output contains all expected flags and descriptions
	if os.Getenv("BE_CRASHER") == "1" {
		// Reset flags
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		versionFlag = flag.Bool("version", false, "print version")
		configFlag = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
		expandEnv = flag.Bool("expandEnv", false, "expand environment variables in config file")

		os.Args = []string{"oidc-discovery-provider", "unexpected"}
		main()
		return
	}

	// #nosec G204 - os.Args[0] is safe in test context
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_UsageOutput")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	require.Error(t, err) // Should exit with error

	output := stderr.String()

	// Verify all expected usage components are present
	expectedComponents := []string{
		"Error: unexpected arguments:",
		"Usage of",
		"-config string",
		"configuration file (default \"oidc-discovery-provider.conf\")",
		"-expandEnv",
		"expand environment variables in config file",
		"-version",
		"print version",
	}

	for _, component := range expectedComponents {
		require.Contains(t, output, component, "Usage output should contain: %s", component)
	}
}

func TestMain_FlagParsing(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedConfig string
		expectedExpand bool
	}{
		{
			name:           "default values",
			args:           []string{},
			expectedConfig: "oidc-discovery-provider.conf",
			expectedExpand: false,
		},
		{
			name:           "custom config",
			args:           []string{"-config", "custom.conf"},
			expectedConfig: "custom.conf",
			expectedExpand: false,
		},
		{
			name:           "expand env enabled",
			args:           []string{"-expandEnv"},
			expectedConfig: "oidc-discovery-provider.conf",
			expectedExpand: true,
		},
		{
			name:           "both flags",
			args:           []string{"-config", "test.conf", "-expandEnv"},
			expectedConfig: "test.conf",
			expectedExpand: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flags for each test
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
			versionFlag = flag.Bool("version", false, "print version")
			configFlag = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
			expandEnv = flag.Bool("expandEnv", false, "expand environment variables in config file")

			// Parse the test arguments
			err := flag.CommandLine.Parse(tt.args)
			require.NoError(t, err)

			// Verify flag values
			require.Equal(t, tt.expectedConfig, *configFlag)
			require.Equal(t, tt.expectedExpand, *expandEnv)
		})
	}
}

func TestMain_Integration(t *testing.T) {
	// Test that the main function properly handles the flow from flag parsing to run()
	// This test focuses on the argument validation without actually running the server

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid flags only",
			args:        []string{"-config", "nonexistent.conf"},
			expectError: true, // Will fail at LoadConfig, but not at arg validation
			errorMsg:    "",   // No specific error message for arg validation
		},
		{
			name:        "invalid positional args",
			args:        []string{"-config", "test.conf", "badarg"},
			expectError: true,
			errorMsg:    "unexpected arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if os.Getenv("BE_CRASHER") == "1" {
				// Reset flags
				flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
				versionFlag = flag.Bool("version", false, "print version")
				configFlag = flag.String("config", "oidc-discovery-provider.conf", "configuration file")
				expandEnv = flag.Bool("expandEnv", false, "expand environment variables in config file")

				os.Args = append([]string{"oidc-discovery-provider"}, tt.args...)
				main()
				return
			}

			// #nosec G204 - os.Args[0] is safe in test context
			cmd := exec.Command(os.Args[0], "-test.run=TestMain_Integration/"+tt.name)
			cmd.Env = append(os.Environ(), "BE_CRASHER=1")

			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					require.Contains(t, stderr.String(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
