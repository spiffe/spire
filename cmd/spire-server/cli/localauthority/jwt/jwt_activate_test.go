package jwt_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	authority_common "github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/spiffe/spire/cmd/spire-server/cli/localauthority/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestJWTActivateHelp(t *testing.T) {
	test := authority_common.SetupTest(t, jwt.NewJWTActivateCommandWithEnv)

	test.Client.Help()
	require.Equal(t, jwtActivateUsage, test.Stderr.String())
}

func TestJWTActivateSynopsys(t *testing.T) {
	test := authority_common.SetupTest(t, jwt.NewJWTActivateCommandWithEnv)
	require.Equal(t, "Activates a prepared JWT authority for use, which will cause it to be used for all JWT signing operations serviced by this server going forward", test.Client.Synopsis())
}

func TestJWTActivate(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error
		active, prepared   *localauthorityv1.AuthorityState
	}{
		{
			name:             "success",
			expectReturnCode: 0,
			args:             []string{"-authorityID", "prepared-id"},
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			expectStdoutPretty: "Activated JWT authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n",
			expectStdoutJSON:   `{"activated_authority":{"authority_id":"active-id","expires_at":"1001"}}`,
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
			args:             []string{"-authorityID", "prepared-id"},
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not activate JWT authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authority_common.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authority_common.SetupTest(t, jwt.NewJWTActivateCommandWithEnv)
				test.Server.ActiveJWT = tt.active
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
