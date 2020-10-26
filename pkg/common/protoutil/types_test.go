package protoutil_test

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/require"
)

func TestSPIFFEIDToStr(t *testing.T) {
	id := protoutil.SPIFFEIDToStr(&types.SPIFFEID{TrustDomain: "example.org", Path: "/host"})
	require.Equal(t, "spiffe://example.org/host", id)
}

func TestStrToSPIFFEID(t *testing.T) {
	id, err := protoutil.StrToSPIFFEID("spiffe://example.org/host")
	require.NoError(t, err)
	require.Equal(t, types.SPIFFEID{TrustDomain: "example.org", Path: "/host"}, *id)

	id, err = protoutil.StrToSPIFFEID("example.org/host")
	require.Error(t, err)
	require.Nil(t, id)
}
