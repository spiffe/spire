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

func TestX509ShowHelp(t *testing.T) {
	test := authority_common.SetupTest(t, x509.NewX509ShowCommandWithEnv)

	test.Client.Help()
	require.Equal(t, x509ShowUsage, test.Stderr.String())
}

func TestX509ShowSynopsys(t *testing.T) {
	test := authority_common.SetupTest(t, x509.NewX509ShowCommandWithEnv)
	require.Equal(t, "Shows the local X.509 authorities", test.Client.Synopsis())
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
		for _, format := range authority_common.AvailableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := authority_common.SetupTest(t, x509.NewX509ShowCommandWithEnv)
				test.Server.ActiveX509 = tt.active
				test.Server.PreparedX509 = tt.prepared
				test.Server.OldX509 = tt.old
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
