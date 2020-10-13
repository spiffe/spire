package entry

import (
	"testing"

	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/require"
)

func TestIDStringToProto(t *testing.T) {
	id, err := idStringToProto("spiffe://example.org/host")
	require.NoError(t, err)
	require.Equal(t, types.SPIFFEID{TrustDomain: "example.org", Path: "/host"}, *id)

	id, err = idStringToProto("example.org/host")
	require.Error(t, err)
	require.Nil(t, id)
}

func TestProtoToIDString(t *testing.T) {
	id := protoToIDString(&types.SPIFFEID{TrustDomain: "example.org", Path: "/host"})
	require.Equal(t, "spiffe://example.org/host", id)
}
