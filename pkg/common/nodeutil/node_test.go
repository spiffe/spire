package nodeutil_test

import (
	"fmt"
	"testing"

	legacyProto "github.com/golang/protobuf/proto" // nolint:staticcheck // deprecated library needed until WithDetails can take v2
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

func getError(t *testing.T, code codes.Code, details proto.Message) error {
	st := status.New(code, "some error")
	if details != nil {
		var err error
		st, err = st.WithDetails(legacyProto.MessageV1(details))
		require.NoError(t, err)
	}
	return fmt.Errorf("extra info: %w", st.Err())
}
