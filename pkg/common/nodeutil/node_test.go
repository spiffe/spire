package nodeutil_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestIsAgentBanned(t *testing.T) {
	require.True(t, nodeutil.IsAgentBanned(common.AttestedNode{}))
	require.False(t, nodeutil.IsAgentBanned(common.AttestedNode{CertSerialNumber: "non-empty-serial"}))
	require.False(t, nodeutil.IsAgentBanned(common.AttestedNode{NewCertSerialNumber: "non-empty-serial"}))
	require.False(t, nodeutil.IsAgentBanned(common.AttestedNode{
		CertSerialNumber:    "non-empty-serial",
		NewCertSerialNumber: "non-empty-serial",
	}))
}
