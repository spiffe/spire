package nodeutil_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/runtime/protoiface"
)

func TestIsAgentBanned(t *testing.T) {
	require.True(t, nodeutil.IsAgentBanned(&common.AttestedNode{}))
	require.False(t, nodeutil.IsAgentBanned(&common.AttestedNode{CertSerialNumber: "non-empty-serial"}))
}

func TestShouldAgentReattest(t *testing.T) {
	agentExpired := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_EXPIRED,
	}
	agentNotActive := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_NOT_ACTIVE,
	}
	agentNotAttested := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_NOT_ATTESTED,
	}
	agentBanned := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_BANNED,
	}

	require.False(t, nodeutil.ShouldAgentReattest(nil))
	require.True(t, nodeutil.ShouldAgentReattest(getError(t, codes.PermissionDenied, agentExpired)))
	require.True(t, nodeutil.ShouldAgentReattest(getError(t, codes.PermissionDenied, agentNotActive)))
	require.True(t, nodeutil.ShouldAgentReattest(getError(t, codes.PermissionDenied, agentNotAttested)))
	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.PermissionDenied, agentBanned)))

	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.Unknown, agentExpired)))
	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.Unknown, agentNotActive)))
	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.Unknown, agentNotAttested)))
	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.Unknown, agentBanned)))

	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.PermissionDenied, &types.Status{})))
	require.False(t, nodeutil.ShouldAgentReattest(getError(t, codes.PermissionDenied, nil)))
}

func TestIsUnknownAuthority(t *testing.T) {
	t.Run("no error provided", func(t *testing.T) {
		require.False(t, nodeutil.IsUnknownAuthorityError(nil))
	})

	t.Run("unexpected error", func(t *testing.T) {
		require.False(t, nodeutil.IsUnknownAuthorityError(errors.New("oh no")))
	})

	t.Run("unknown authority err", func(t *testing.T) {
		// Create two bundles with same TD and an SVID that is signed by one of them
		ca := testca.New(t, spiffeid.RequireTrustDomainFromString("test.td"))
		ca2 := testca.New(t, spiffeid.RequireTrustDomainFromString("test.td"))
		svid := ca2.CreateX509SVID(spiffeid.RequireFromString("spiffe://test.td/w1"))

		// Verify must fail
		_, _, err := x509svid.Verify(svid.Certificates, ca.X509Bundle())
		require.Error(t, err)

		require.True(t, nodeutil.IsUnknownAuthorityError(err))
	})
}

func TestShouldAgentShutdown(t *testing.T) {
	agentExpired := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_EXPIRED,
	}
	agentNotActive := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_NOT_ACTIVE,
	}
	agentNotAttested := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_NOT_ATTESTED,
	}
	agentBanned := &types.PermissionDeniedDetails{
		Reason: types.PermissionDeniedDetails_AGENT_BANNED,
	}

	require.False(t, nodeutil.ShouldAgentReattest(nil))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.PermissionDenied, agentExpired)))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.PermissionDenied, agentNotActive)))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.PermissionDenied, agentNotAttested)))
	require.True(t, nodeutil.ShouldAgentShutdown(getError(t, codes.PermissionDenied, agentBanned)))

	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.Unknown, agentExpired)))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.Unknown, agentNotActive)))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.Unknown, agentNotAttested)))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.Unknown, agentBanned)))

	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.PermissionDenied, &types.Status{})))
	require.False(t, nodeutil.ShouldAgentShutdown(getError(t, codes.PermissionDenied, nil)))
}

func getError(t *testing.T, code codes.Code, details protoiface.MessageV1) error {
	st := status.New(code, "some error")
	if details != nil {
		var err error
		st, err = st.WithDetails(details)
		require.NoError(t, err)
	}
	return fmt.Errorf("extra info: %w", st.Err())
}
