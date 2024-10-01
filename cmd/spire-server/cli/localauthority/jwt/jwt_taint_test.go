package jwt_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	authoritycommon_test "github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon/test"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/spiffe/spire/cmd/spire-server/cli/localauthority/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestJWTTaintHelp(t *testing.T) {
	test := authoritycommon_test.SetupTest(t, jwt.NewJWTTaintCommandWithEnv)

	test.Client.Help()
	require.Equal(t, jwtTaintUsage, test.Stderr.String())
}

func TestJWTTaintSynopsys(t *testing.T) {
	test := authoritycommon_test.SetupTest(t, jwt.NewJWTTaintCommandWithEnv)
	require.Equal(t, "Marks the previously active JWT authority as being tainted", test.Client.Synopsis())
}

func TestJWTTaint(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error
		tainted            *localauthorityv1.AuthorityState
	}{
		{
			name:             "success",
			expectReturnCode: 0,
			args:             []string{"-authorityID", "prepared-id"},
			tainted: &localauthorityv1.AuthorityState{
				AuthorityId: "tainted-id",
				ExpiresAt:   1001,
			},
			expectStdoutPretty: "Tainted JWT authority:\n  Authority ID: tainted-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n",
			expectStdoutJSON:   `{"tainted_authority":{"authority_id":"tainted-id","expires_at":"1001","upstream_authority_subject_key_id":""}}`,
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
			args:             []string{"-authorityID", "old-id"},
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not taint JWT authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authoritycommon_test.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authoritycommon_test.SetupTest(t, jwt.NewJWTTaintCommandWithEnv)
				test.Server.TaintedJWT = tt.tainted
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
