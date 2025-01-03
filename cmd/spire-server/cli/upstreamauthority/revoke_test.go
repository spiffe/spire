package upstreamauthority_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	authority_common_test "github.com/spiffe/spire/cmd/spire-server/cli/authoritycommon/test"
	"github.com/spiffe/spire/cmd/spire-server/cli/upstreamauthority"
	"github.com/spiffe/spire/test/clitest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestRevokeHelp(t *testing.T) {
	test := authority_common_test.SetupTest(t, upstreamauthority.NewRevokeCommandWithEnv)

	test.Client.Help()
	require.Equal(t, revokeUsage, test.Stderr.String())
}

func TestRevokeSynopsys(t *testing.T) {
	test := authority_common_test.SetupTest(t, upstreamauthority.NewRevokeCommandWithEnv)
	require.Equal(t, "Revokes the previously active X.509 upstream authority by removing it from the bundle and propagating this update throughout the cluster", test.Client.Synopsis())
}

func TestRevoke(t *testing.T) {
	for _, tt := range []struct {
		name                          string
		args                          []string
		expectReturnCode              int
		expectStdoutPretty            string
		expectStdoutJSON              string
		expectStderr                  string
		serverErr                     error
		upstreamAuthoritySubjectKeyId string
	}{
		{
			name:                          "success",
			expectReturnCode:              0,
			args:                          []string{"-subjectKeyID", "subject-key-id"},
			upstreamAuthoritySubjectKeyId: "subject-key-id",
			expectStdoutPretty:            "Revoked X.509 upstream authority:\n  Subject Key ID: subject-key-id\n",
			expectStdoutJSON:              `{"upstream_authority_subject_key_id":"subject-key-id"}`,
		},
		{
			name:             "no subject key id",
			expectReturnCode: 1,
			expectStderr:     "Error: the Subject Key ID of the X.509 upstream authority is required\n",
		},
		{
			name: "wrong UDS path",
			args: []string{
				clitest.AddrArg, clitest.AddrValue,
				"-subjectKeyID", "subject-key-id",
			},
			expectReturnCode: 1,
			expectStderr:     "Error: could not revoke X.509 upstream authority: " + clitest.AddrError,
		},
		{
			name:             "server error",
			args:             []string{"-subjectKeyID", "some-id"},
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: could not revoke X.509 upstream authority: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range authority_common_test.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authority_common_test.SetupTest(t, upstreamauthority.NewRevokeCommandWithEnv)
				test.Server.RevokedUpstreamAuthoritySubjectKeyId = tt.upstreamAuthoritySubjectKeyId
				test.Server.Err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.Client.Run(append(test.Args, args...))

				authority_common_test.RequireOutputBasedOnFormat(t, format, test.Stdout.String(), tt.expectStdoutPretty, tt.expectStdoutJSON)
				require.Equal(t, tt.expectStderr, test.Stderr.String())
				require.Equal(t, tt.expectReturnCode, returnCode)
			})
		}
	}
}
