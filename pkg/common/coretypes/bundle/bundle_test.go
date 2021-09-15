package bundle_test

import (
	"crypto/x509"
	"testing"
	"time"

	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/bundle"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
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
	root, _               = pemutil.ParseCertificate(rootPEM)
	expiresAt             = time.Now().Truncate(time.Second)
	publicKey             = testkey.MustEC256().Public()
	pkixBytes, _          = x509.MarshalPKIXPublicKey(publicKey)
	apiJWTAuthoritiesGood = []*apitypes.JWTKey{
		{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()},
	}
	apiJWTAuthoritiesBad = []*apitypes.JWTKey{
		{PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()},
	}
	apiX509AuthoritiesGood = []*apitypes.X509Certificate{
		{Asn1: root.Raw},
	}
	apiX509AuthoritiesBad = []*apitypes.X509Certificate{
		{Asn1: []byte("malformed")},
	}
	apiGood = &apitypes.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: apiX509AuthoritiesGood,
		JwtAuthorities:  apiJWTAuthoritiesGood,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	apiInvalidTD = &apitypes.Bundle{
		TrustDomain:     "no a trustdomain",
		X509Authorities: apiX509AuthoritiesGood,
		JwtAuthorities:  apiJWTAuthoritiesGood,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	apiInvalidX509Authorities = &apitypes.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: apiX509AuthoritiesBad,
		JwtAuthorities:  apiJWTAuthoritiesGood,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	apiInvalidJWTAutorities = &apitypes.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: apiX509AuthoritiesGood,
		JwtAuthorities:  apiJWTAuthoritiesBad,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	pluginJWTAuthoritiesGood = []*plugintypes.JWTKey{
		{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()},
	}
	pluginJWTAuthoritiesBad = []*plugintypes.JWTKey{
		{PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()},
	}
	pluginX509AuthoritiesGood = []*plugintypes.X509Certificate{
		{Asn1: root.Raw},
	}
	pluginX509AuthoritiesBad = []*plugintypes.X509Certificate{
		{Asn1: []byte("malformed")},
	}
	pluginGood = &plugintypes.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: pluginX509AuthoritiesGood,
		JwtAuthorities:  pluginJWTAuthoritiesGood,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	pluginInvalidTD = &plugintypes.Bundle{
		TrustDomain:     "no a trustdomain",
		X509Authorities: pluginX509AuthoritiesGood,
		JwtAuthorities:  pluginJWTAuthoritiesGood,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	pluginInvalidX509Authorities = &plugintypes.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: pluginX509AuthoritiesBad,
		JwtAuthorities:  pluginJWTAuthoritiesGood,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	pluginInvalidJWTAutorities = &plugintypes.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: pluginX509AuthoritiesGood,
		JwtAuthorities:  pluginJWTAuthoritiesBad,
		RefreshHint:     1,
		SequenceNumber:  2,
	}
	commonGood = &common.Bundle{
		TrustDomainId:  "spiffe://example.org",
		RootCas:        []*common.Certificate{{DerBytes: root.Raw}},
		JwtSigningKeys: []*common.PublicKey{{Kid: "ID", PkixBytes: pkixBytes, NotAfter: expiresAt.Unix()}},
		RefreshHint:    1,
	}
)

func TestToPluginFromAPIProto(t *testing.T) {
	assertOK := func(t *testing.T, in *apitypes.Bundle, expectOut *plugintypes.Bundle) {
		actualOut, err := bundle.ToPluginFromAPIProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in *apitypes.Bundle, expectErr string) {
		actualOut, err := bundle.ToPluginFromAPIProto(in)
		spiretest.RequireErrorContains(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, apiGood, pluginGood)
	assertFail(t, apiInvalidTD, "malformed trust domain:")
	assertFail(t, apiInvalidX509Authorities, "invalid X.509 authority: failed to parse X.509 certificate data: ")
	assertFail(t, apiInvalidJWTAutorities, "invalid JWT authority: missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToCommonFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.Bundle, expectOut *common.Bundle) {
		actualOut, err := bundle.ToCommonFromPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, bundle.RequireToCommonFromPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *plugintypes.Bundle, expectErr string) {
		actualOut, err := bundle.ToCommonFromPluginProto(in)
		spiretest.RequireErrorContains(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { bundle.RequireToCommonFromPluginProto(in) })
	}

	assertOK(t, pluginGood, commonGood)
	assertFail(t, pluginInvalidTD, "malformed trust domain:")
	assertFail(t, pluginInvalidX509Authorities, "invalid X.509 authority: failed to parse X.509 certificate data: ")
	assertFail(t, pluginInvalidJWTAutorities, "invalid JWT authority: missing key ID for JWT key")
	assertOK(t, nil, nil)
}
