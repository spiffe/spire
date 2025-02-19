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

func TestJWTPrepareHelp(t *testing.T) {
	test := authoritycommon_test.SetupTest(t, jwt.NewJWTPrepareCommandWithEnv)

	test.Client.Help()
	require.Equal(t, jwtPrepareUsage, test.Stderr.String())
}

func TestJWTPrepareSynopsys(t *testing.T) {
	test := authoritycommon_test.SetupTest(t, jwt.NewJWTPrepareCommandWithEnv)
	require.Equal(t, "Prepares a new JWT authority for use by generating a new key and injecting it into the bundle", test.Client.Synopsis())
}

func TestJWTPrepare(t *testing.T) {
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
			expectStdoutPretty: "Prepared JWT authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n",
			expectStdoutJSON:   `{"prepared_authority":{"authority_id":"prepared-id","expires_at":"1002","upstream_authority_subject_key_id":""}}`,
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
		},
		{
			name:             "wrong UDS path",
			args:             []string{clitest.AddrArg, clitest.AddrValue},
			expectReturnCode: 1,
			expectStderr:     "Error: could not prepare JWT authority: " + clitest.AddrError,
		},
		{
			name:             "server error",
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not prepare JWT authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authoritycommon_test.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authoritycommon_test.SetupTest(t, jwt.NewJWTPrepareCommandWithEnv)
				test.Server.PreparedJWT = tt.prepared
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
