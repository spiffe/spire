package nodeutil_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsAgentBanned(t *testing.T) {
	require.True(t, nodeutil.IsAgentBanned(&common.AttestedNode{}))
	require.False(t, nodeutil.IsAgentBanned(&common.AttestedNode{CertSerialNumber: "non-empty-serial"}))
}

func TestIsShutdownError(t *testing.T) {
	require.True(t, nodeutil.IsShutdownError(getError(t, codes.PermissionDenied, types.PermissionDeniedDetails_AGENT_EXPIRED)))
	require.True(t, nodeutil.IsShutdownError(getError(t, codes.PermissionDenied, types.PermissionDeniedDetails_AGENT_NOT_ACTIVE)))
	require.True(t, nodeutil.IsShutdownError(getError(t, codes.PermissionDenied, types.PermissionDeniedDetails_AGENT_NOT_ATTESTED)))
	require.False(t, nodeutil.IsShutdownError(getError(t, codes.PermissionDenied, types.PermissionDeniedDetails_AGENT_BANNED)))
	require.False(t, nodeutil.IsShutdownError(getError(t, codes.Unknown, types.PermissionDeniedDetails_AGENT_EXPIRED)))
	require.False(t, nodeutil.IsShutdownError(getError(t, codes.Unknown, types.PermissionDeniedDetails_AGENT_NOT_ACTIVE)))
	require.False(t, nodeutil.IsShutdownError(getError(t, codes.Unknown, types.PermissionDeniedDetails_AGENT_NOT_ATTESTED)))
}

func getError(t *testing.T, code codes.Code, reason types.PermissionDeniedDetails_Reason) error {
	st := status.New(code, "some error")
	detailed, err := st.WithDetails(&types.PermissionDeniedDetails{
		Reason: reason,
	})
	require.NoError(t, err)
	return detailed.Err()
}
