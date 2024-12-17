package jwt_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	authoritycommon_test "github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon/test"
	"github.com/spiffe/spire/cmd/spire-server/cli/localauthority/jwt"
	"github.com/spiffe/spire/test/clitest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestJWTRevokeHelp(t *testing.T) {
	test := authoritycommon_test.SetupTest(t, jwt.NewJWTRevokeCommandWithEnv)

	test.Client.Help()
	require.Equal(t, jwtRevokeUsage, test.Stderr.String())
}

func TestJWTRevokeSynopsys(t *testing.T) {
	test := authoritycommon_test.SetupTest(t, jwt.NewJWTRevokeCommandWithEnv)
	require.Equal(t, "Revokes the previously active JWT authority by removing it from the bundle and propagating this update throughout the cluster", test.Client.Synopsis())
}

func TestJWTRevoke(t *testing.T) {
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
			expectStdoutPretty: "Revoked JWT authority:\n  Authority ID: revoked-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n",
			expectStdoutJSON:   `{"revoked_authority":{"authority_id":"revoked-id","expires_at":"1001","upstream_authority_subject_key_id":""}}`,
		},
		{
			name:             "no authority id",
			expectReturnCode: 1,
			expectStderr:     "Error: an authority ID is required\n",
		},
		{
			name: "wrong UDS path",
			args: []string{
				clitest.AddrArg, clitest.AddrValue,
				"-authorityID", "prepared-id",
			},
			expectReturnCode: 1,
			expectStderr:     "Error: could not revoke JWT authority: " + clitest.AddrError,
		},
		{
			name:             "server error",
			args:             []string{"-authorityID", "tainted-id"},
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not revoke JWT authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authoritycommon_test.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authoritycommon_test.SetupTest(t, jwt.NewJWTRevokeCommandWithEnv)
				test.Server.RevokedJWT = tt.revoked
				test.Server.Err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.Client.Run(append(test.Args, args...))

				authoritycommon_test.RequireOutputBasedOnFormat(t, format, test.Stdout.String(), tt.expectStdoutPretty, tt.expectStdoutJSON)
				require.Equal(t, tt.expectStderr, test.Stderr.String())
				require.Equal(t, tt.expectReturnCode, returnCode)
			})
		}
	}
}
