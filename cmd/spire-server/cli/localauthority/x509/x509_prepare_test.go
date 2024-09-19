package x509_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	authority_common "github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/spiffe/spire/cmd/spire-server/cli/localauthority/x509"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestX509PrepareHelp(t *testing.T) {
	test := authority_common.SetupTest(t, x509.NewX509PrepareCommandWithEnv)

	test.Client.Help()
	require.Equal(t, x509PrepareUsage, test.Stderr.String())
}

func TestX509PrepareSynopsys(t *testing.T) {
	test := authority_common.SetupTest(t, x509.NewX509PrepareCommandWithEnv)
	require.Equal(t, "Prepares a new X.509 authority for use by generating a new key and injecting the resulting CA certificate into the bundle", test.Client.Synopsis())
}

func TestX509Prepare(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error
		prepared           *localauthorityv1.AuthorityState
	}{
		{
			name:               "success",
			expectReturnCode:   0,
			expectStdoutPretty: "Prepared X.509 authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n",
			expectStdoutJSON:   `{"prepared_authority":{"authority_id":"prepared-id","expires_at":"1002"}}`,
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
		},
		{
			name:             "wrong UDS path",
			args:             []string{common.AddrArg, common.AddrValue},
			expectReturnCode: 1,
			expectStderr:     common.AddrError,
		},
		{
			name:             "server error",
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not prepare X.509 authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authority_common.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authority_common.SetupTest(t, x509.NewX509PrepareCommandWithEnv)
				test.Server.PreparedX509 = tt.prepared
				test.Server.Err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.Client.Run(append(test.Args, args...))

				authority_common.RequireOutputBasedOnFormat(t, format, test.Stdout.String(), tt.expectStdoutPretty, tt.expectStdoutJSON)
				require.Equal(t, tt.expectStderr, test.Stderr.String())
				require.Equal(t, tt.expectReturnCode, returnCode)
			})
		}
	}
}
