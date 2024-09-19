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

func TestX509RevokeHelp(t *testing.T) {
	test := authority_common.SetupTest(t, x509.NewX509RevokeCommandWithEnv)

	test.Client.Help()
	require.Equal(t, x509RevokeUsage, test.Stderr.String())
}

func TestX509RevokeSynopsys(t *testing.T) {
	test := authority_common.SetupTest(t, x509.NewX509RevokeCommandWithEnv)
	require.Equal(t, "Revokes the previously active X.509 authority by removing it from the bundle and propagating this update throughout the cluster", test.Client.Synopsis())
}

func TestX509Revoke(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error
		revoked            *localauthorityv1.AuthorityState
	}{
		{
			name:             "success",
			expectReturnCode: 0,
			args:             []string{"-authorityID", "prepared-id"},
			revoked: &localauthorityv1.AuthorityState{
				AuthorityId: "revoked-id",
				ExpiresAt:   1001,
			},
			expectStdoutPretty: "Revoked X.509 authority:\n  Authority ID: revoked-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n",
			expectStdoutJSON:   `{"revoked_authority":{"authority_id":"revoked-id","expires_at":"1001"}}`,
		},
		{
			name:             "no authority id",
			expectReturnCode: 1,
			expectStderr:     "Error: an authority ID is required\n",
		},
		{
			name:             "wrong UDS path",
			args:             []string{common.AddrArg, common.AddrValue},
			expectReturnCode: 1,
			expectStderr:     common.AddrError,
		},
		{
			name:             "server error",
			args:             []string{"-authorityID", "tainted-id"},
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not revoke X.509 authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authority_common.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authority_common.SetupTest(t, x509.NewX509RevokeCommandWithEnv)
				test.Server.RevokedX509 = tt.revoked
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
