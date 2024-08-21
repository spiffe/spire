package localauthority_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/spiffe/spire/cmd/spire-server/cli/localauthority"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestX509ShowHelp(t *testing.T) {
	test := setupTest(t, localauthority.NewX509ShowCommandWithEnv)

	test.client.Help()
	require.Equal(t, x509ShowUsage, test.stderr.String())
}

func TestX509ShowSynopsys(t *testing.T) {
	test := setupTest(t, localauthority.NewX509ShowCommandWithEnv)
	require.Equal(t, "Shows the local X.509 authorities", test.client.Synopsis())
}

func TestX509Show(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error

		active,
		prepared,
		old *localauthorityv1.AuthorityState
	}{
		{
			name:             "success",
			expectReturnCode: 0,
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			old: &localauthorityv1.AuthorityState{
				AuthorityId: "old-id",
				ExpiresAt:   1003,
			},
			expectStdoutPretty: "Active X.509 authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n\nPrepared X.509 authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n\nOld X.509 authority:\n  Authority ID: old-id\n  Expires at: 1970-01-01 00:16:43 +0000 UTC\n",
			expectStdoutJSON:   `{"active":{"authority_id":"active-id","expires_at":"1001"},"prepared":{"authority_id":"prepared-id","expires_at":"1002"},"old":{"authority_id":"old-id","expires_at":"1003"}}`,
		},
		{
			name:             "success - no active",
			expectReturnCode: 0,
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			old: &localauthorityv1.AuthorityState{
				AuthorityId: "old-id",
				ExpiresAt:   1003,
			},
			expectStdoutPretty: "Active X.509 authority:\n  No active X.509 authority found\n\nPrepared X.509 authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n\nOld X.509 authority:\n  Authority ID: old-id\n  Expires at: 1970-01-01 00:16:43 +0000 UTC\n",
			expectStdoutJSON:   `{"prepared":{"authority_id":"prepared-id","expires_at":"1002"},"old":{"authority_id":"old-id","expires_at":"1003"}}`,
		},
		{
			name:             "success - no prepared",
			expectReturnCode: 0,
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			old: &localauthorityv1.AuthorityState{
				AuthorityId: "old-id",
				ExpiresAt:   1003,
			},
			expectStdoutPretty: "Active X.509 authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n\nPrepared X.509 authority:\n  No prepared X.509 authority found\n\nOld X.509 authority:\n  Authority ID: old-id\n  Expires at: 1970-01-01 00:16:43 +0000 UTC\n",
			expectStdoutJSON:   `{"active":{"authority_id":"active-id","expires_at":"1001"},"old":{"authority_id":"old-id","expires_at":"1003"}}`,
		},
		{
			name:             "success - no old",
			expectReturnCode: 0,
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			expectStdoutPretty: "Active X.509 authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n\nPrepared X.509 authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n\nOld X.509 authority:\n  No old X.509 authority found\n",
			expectStdoutJSON:   `{"active":{"authority_id":"active-id","expires_at":"1001"},"prepared":{"authority_id":"prepared-id","expires_at":"1002"}}`,
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
			expectStderr:     "Error: could not get X.509 authorities: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, localauthority.NewX509ShowCommandWithEnv)
				test.server.activeX509 = tt.active
				test.server.preparedX509 = tt.prepared
				test.server.oldX509 = tt.old
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectStdoutPretty, tt.expectStdoutJSON)
				require.Equal(t, tt.expectStderr, test.stderr.String())
				require.Equal(t, tt.expectReturnCode, returnCode)
			})
		}
	}
}
