package workload

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/spire/proto/spire/api/workload"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

func TestProtoToX509SVID(t *testing.T) {
	name := "spiffe://foo/bar"
	testSVID, testKey, err := util.LoadSVIDFixture()
	require.NoError(t, err)
	ca, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	keyData, err := x509.MarshalPKCS8PrivateKey(testKey)
	require.NoError(t, err)

	svidMsg := &workload.X509SVID{
		SpiffeId:    name,
		X509Svid:    testSVID.Raw,
		X509SvidKey: keyData,
		Bundle:      ca.Raw,
	}
	svid, err := protoToX509SVID(svidMsg)
	require.NoError(t, err)
	require.Equal(t, name, svid.SPIFFEID)
	require.Equal(t, testKey, svid.PrivateKey)
	require.Equal(t, testSVID, svid.Certificates[0])
	require.Equal(t, ca, svid.TrustBundle[0])
}
