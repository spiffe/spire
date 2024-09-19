package x509certificate_test

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-cmp/cmp"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	rootPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBRzCB76ADAgECAgEBMAoGCCqGSM49BAMCMBMxETAPBgNVBAMTCEFnZW50IENB
MCAYDzAwMDEwMTAxMDAwMDAwWhcNMjEwNTI2MjE1MDA5WjATMREwDwYDVQQDEwhB
Z2VudCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNRTee0Z/+omKGAVU3Ns
NkOrpvcU4gZ3C6ilHSfYUiF2o+YCdsuLZb8UFbEVB4VR1H7Ez629IPEASK1k0KW+
KHajMjAwMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFAXjxsTxL8UIBZl5lheq
qaDOcBhNMAoGCCqGSM49BAMCA0cAMEQCIGTDiqcBaFomiRIfRNtLNTl5wFIQMlcB
MWnIPs59/JF8AiBeKSM/rkL2igQchDTvlJJWsyk9YL8UZI/XfZO7907TWA==
-----END CERTIFICATE-----`)
	leafPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBQTCB6aADAgECAgEAMAoGCCqGSM49BAMCMBMxETAPBgNVBAMTCEFnZW50IENB
MCAYDzAwMDEwMTAxMDAwMDAwWhcNMjEwNTI2MjE1MDA5WjAMMQowCAYDVQQDEwFh
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1xgPV8gA9Cwc3IteMLvKjNnZ1QTW
4Zj75j0J52M7HwwahurzSH9fHa7mKqMXHulEeDo9n6tt3iS3fi14J2WtzqMzMDEw
DgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFAXjxsTxL8UIBZl5lheqqaDOcBhN
MAoGCCqGSM49BAMCA0cAMEQCIHf/4m7fPB238z+aPaCuMj019SgA9o3ocdj0yvTx
ozrYAiBrdSwMwUG795ZY1D5lh5s0mHb98muSjR3EoPPSiadJtA==
-----END CERTIFICATE-----`)
	root, _              = pemutil.ParseCertificate(rootPEM)
	leaf, _              = pemutil.ParseCertificate(leafPEM)
	rootAuthority        = &x509certificate.X509Authority{Certificate: root}
	leafAuthority        = &x509certificate.X509Authority{Certificate: leaf}
	leafTaintedAuthority = &x509certificate.X509Authority{Certificate: leaf, Tainted: true}
	empty                = &x509.Certificate{}
	emptyAuthority       = &x509certificate.X509Authority{}
	emptyAuthorityCert   = &x509certificate.X509Authority{Certificate: &x509.Certificate{}}
	junk                 = []byte("JUNK")
	pluginRoot           = &plugintypes.X509Certificate{Asn1: root.Raw}
	pluginLeaf           = &plugintypes.X509Certificate{Asn1: leaf.Raw}
	pluginTaintedLeaf    = &plugintypes.X509Certificate{Asn1: leaf.Raw, Tainted: true}
	pluginEmpty          = &plugintypes.X509Certificate{}
	pluginBad            = &plugintypes.X509Certificate{Asn1: junk}
	commonRoot           = &common.Certificate{DerBytes: root.Raw}
	commonLeaf           = &common.Certificate{DerBytes: leaf.Raw}
	commonTaintedLeaf    = &common.Certificate{DerBytes: leaf.Raw, TaintedKey: true}
	commonEmpty          = &common.Certificate{}
	commonBad            = &common.Certificate{DerBytes: junk}
	apiLeaf              = &apitypes.X509Certificate{Asn1: leaf.Raw}
	apiTaintedLeaf       = &apitypes.X509Certificate{Asn1: leaf.Raw, Tainted: true}
	apiEmpty             = &apitypes.X509Certificate{}
)

func TestFromCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in *common.Certificate, expectOut *x509certificate.X509Authority) {
		actualOut, err := x509certificate.FromCommonProto(in)
		require.NoError(t, err)
		assertX509CertificateEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertX509CertificateEqual(t, expectOut, x509certificate.RequireFromCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in *common.Certificate, expectErr string) {
		actualOut, err := x509certificate.FromCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireFromCommonProto(in) })
	}

	assertOK(t, commonLeaf, leafAuthority)
	assertOK(t, commonTaintedLeaf, leafTaintedAuthority)
	assertFail(t, commonEmpty, "missing X.509 certificate data")
	assertFail(t, commonBad, "failed to parse X.509 certificate data: ")
}

func TestFromCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*common.Certificate, expectOut []*x509certificate.X509Authority) {
		actualOut, err := x509certificate.FromCommonProtos(in)
		require.NoError(t, err)
		assertX509CertificatesEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertX509CertificatesEqual(t, expectOut, x509certificate.RequireFromCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*common.Certificate, expectErr string) {
		actualOut, err := x509certificate.FromCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireFromCommonProtos(in) })
	}

	assertOK(t, []*common.Certificate{commonLeaf, commonRoot}, []*x509certificate.X509Authority{leafAuthority, rootAuthority})
	assertOK(t, []*common.Certificate{commonTaintedLeaf, commonRoot}, []*x509certificate.X509Authority{leafTaintedAuthority, rootAuthority})
	assertFail(t, []*common.Certificate{commonEmpty}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in *x509certificate.X509Authority, expectOut *common.Certificate) {
		actualOut, err := x509certificate.ToCommonProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, x509certificate.RequireToCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in *x509certificate.X509Authority, expectErr string) {
		actualOut, err := x509certificate.ToCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireToCommonProto(in) })
	}

	assertOK(t, leafAuthority, commonLeaf)
	assertFail(t, nil, "missing x509 authority")
	assertFail(t, emptyAuthority, "missing X.509 certificate")
	assertFail(t, emptyAuthorityCert, "missing X.509 certificate data")
}

func TestToCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*x509certificate.X509Authority, expectOut []*common.Certificate) {
		actualOut, err := x509certificate.ToCommonProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, x509certificate.RequireToCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*x509certificate.X509Authority, expectErr string) {
		actualOut, err := x509certificate.ToCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireToCommonProtos(in) })
	}

	assertOK(t, []*x509certificate.X509Authority{leafAuthority}, []*common.Certificate{commonLeaf})
	assertOK(t, []*x509certificate.X509Authority{leafTaintedAuthority}, []*common.Certificate{commonTaintedLeaf})
	assertFail(t, []*x509certificate.X509Authority{emptyAuthority}, "missing X.509 certificate")
	assertFail(t, []*x509certificate.X509Authority{emptyAuthorityCert}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToCommonFromPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*plugintypes.X509Certificate, expectOut []*common.Certificate) {
		actualOut, err := x509certificate.ToCommonFromPluginProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() {
			spiretest.AssertProtoListEqual(t, expectOut, x509certificate.RequireToCommonFromPluginProtos(in))
		})
	}

	assertFail := func(t *testing.T, in []*plugintypes.X509Certificate, expectErr string) {
		actualOut, err := x509certificate.ToCommonFromPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireToCommonFromPluginProtos(in) })
	}

	assertOK(t, []*plugintypes.X509Certificate{pluginLeaf, pluginTaintedLeaf},
		[]*common.Certificate{commonLeaf, commonTaintedLeaf})
	assertFail(t, []*plugintypes.X509Certificate{pluginEmpty}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.X509Certificate, expectOut *x509certificate.X509Authority) {
		actualOut, err := x509certificate.FromPluginProto(in)
		require.NoError(t, err)
		assertX509CertificateEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertX509CertificateEqual(t, expectOut, x509certificate.RequireFromPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *plugintypes.X509Certificate, expectErr string) {
		actualOut, err := x509certificate.FromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireFromPluginProto(in) })
	}

	assertOK(t, pluginLeaf, leafAuthority)
	assertFail(t, pluginEmpty, "missing X.509 certificate data")
	assertFail(t, pluginBad, "failed to parse X.509 certificate data: ")
}

func TestFromPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*plugintypes.X509Certificate, expectOut []*x509certificate.X509Authority) {
		actualOut, err := x509certificate.FromPluginProtos(in)
		require.NoError(t, err)
		assertX509CertificatesEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertX509CertificatesEqual(t, expectOut, x509certificate.RequireFromPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*plugintypes.X509Certificate, expectErr string) {
		actualOut, err := x509certificate.FromPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireFromPluginProtos(in) })
	}

	assertOK(t, []*plugintypes.X509Certificate{pluginLeaf, pluginRoot}, []*x509certificate.X509Authority{leafAuthority, rootAuthority})
	assertFail(t, []*plugintypes.X509Certificate{pluginEmpty}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *x509certificate.X509Authority, expectOut *plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, x509certificate.RequireToPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *x509certificate.X509Authority, expectErr string) {
		actualOut, err := x509certificate.ToPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireToPluginProto(in) })
	}

	assertOK(t, leafAuthority, pluginLeaf)
	assertFail(t, nil, "missing x509 authority")
	assertFail(t, emptyAuthority, "missing X.509 certificate")
	assertFail(t, emptyAuthorityCert, "missing X.509 certificate data")
}

func TestToPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*x509certificate.X509Authority, expectOut []*plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, x509certificate.RequireToPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*x509certificate.X509Authority, expectErr string) {
		actualOut, err := x509certificate.ToPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireToPluginProtos(in) })
	}

	assertOK(t, []*x509certificate.X509Authority{leafAuthority}, []*plugintypes.X509Certificate{pluginLeaf})
	assertFail(t, []*x509certificate.X509Authority{emptyAuthority}, "missing X.509 certificate")
	assertFail(t, []*x509certificate.X509Authority{emptyAuthorityCert}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToPluginFromCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*common.Certificate, expectOut []*plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginFromCommonProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() {
			spiretest.AssertProtoListEqual(t, expectOut, x509certificate.RequireToPluginFromCommonProtos(in))
		})
	}

	assertFail := func(t *testing.T, in []*common.Certificate, expectErr string) {
		actualOut, err := x509certificate.ToPluginFromCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { x509certificate.RequireToPluginFromCommonProtos(in) })
	}

	assertOK(t, []*common.Certificate{commonLeaf, commonTaintedLeaf}, []*plugintypes.X509Certificate{pluginLeaf, pluginTaintedLeaf})
	assertFail(t, []*common.Certificate{commonEmpty}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToPluginFromAPIProto(t *testing.T) {
	assertOK := func(t *testing.T, in *apitypes.X509Certificate, expectOut *plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginFromAPIProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in *apitypes.X509Certificate, expectErr string) {
		actualOut, err := x509certificate.ToPluginFromAPIProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, apiLeaf, pluginLeaf)
	assertOK(t, apiTaintedLeaf, pluginTaintedLeaf)
	assertFail(t, apiEmpty, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToPluginFromAPIProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*apitypes.X509Certificate, expectOut []*plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginFromAPIProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in []*apitypes.X509Certificate, expectErr string) {
		actualOut, err := x509certificate.ToPluginFromAPIProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, []*apitypes.X509Certificate{apiLeaf, apiTaintedLeaf},
		[]*plugintypes.X509Certificate{pluginLeaf, pluginTaintedLeaf})
	assertFail(t, []*apitypes.X509Certificate{apiEmpty}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}

func TestToPluginFromCertificate(t *testing.T) {
	assertOK := func(t *testing.T, in *x509.Certificate, expectOut *plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginFromCertificate(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in *x509.Certificate, expectErr string) {
		actualOut, err := x509certificate.ToPluginFromCertificate(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, leaf, pluginLeaf)
	assertFail(t, nil, "missing X.509 certificate")
	assertFail(t, empty, "missing X.509 certificate data")
}

func TestToPluginFromCertificates(t *testing.T) {
	assertOK := func(t *testing.T, in []*x509.Certificate, expectOut []*plugintypes.X509Certificate) {
		actualOut, err := x509certificate.ToPluginFromCertificates(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in []*x509.Certificate, expectErr string) {
		actualOut, err := x509certificate.ToPluginFromCertificates(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, []*x509.Certificate{leaf},
		[]*plugintypes.X509Certificate{pluginLeaf})
	assertFail(t, []*x509.Certificate{empty}, "missing X.509 certificate data")
	assertOK(t, nil, nil)
}
func assertX509CertificatesEqual(t *testing.T, expected, actual []*x509certificate.X509Authority) {
	assert.Empty(t, cmp.Diff(expected, actual))
}

func assertX509CertificateEqual(t *testing.T, expected, actual *x509certificate.X509Authority) {
	assert.Empty(t, cmp.Diff(expected, actual))
}
