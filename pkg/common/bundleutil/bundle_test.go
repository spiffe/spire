package bundleutil

// Basic imports
import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/util"
)

type bundleTest struct {
	currentTime      time.Time
	certNotExpired   *x509.Certificate
	certExpired      *x509.Certificate
	jwtKeyExpired    *common.PublicKey
	jwtKeyNotExpired *common.PublicKey
}

func TestPruneBundle(t *testing.T) {
	test := setupTest(t)

	for _, tt := range []struct {
		name        string
		bundle      *common.Bundle
		newBundle   *common.Bundle
		expiration  time.Time
		changed     bool
		expectedErr string
	}{
		{
			name:        "current bundle is nil",
			expiration:  time.Now(),
			expectedErr: "current bundle is nil",
		},
		{
			name: "fail if timeis zero",
			bundle: createBundle(
				[]*x509.Certificate{test.certNotExpired, test.certExpired},
				[]*common.PublicKey{test.jwtKeyNotExpired, test.jwtKeyExpired},
			),
			expiration:  time.Time{},
			expectedErr: "expiration time is zero value",
		},
		{
			name: "fail if all X509 certs expired",
			bundle: createBundle(
				[]*x509.Certificate{test.certExpired},
				[]*common.PublicKey{test.jwtKeyNotExpired, test.jwtKeyExpired},
			),
			expiration:  test.currentTime,
			expectedErr: "would prune all certificates",
		},
		{
			name: "fail if all JWT expired",
			bundle: createBundle(
				[]*x509.Certificate{test.certNotExpired, test.certExpired},
				[]*common.PublicKey{test.jwtKeyExpired},
			),
			expiration:  test.currentTime,
			expectedErr: "would prune all JWT signing keys",
		},
		{
			name: "succeeds",
			bundle: createBundle(
				[]*x509.Certificate{test.certNotExpired, test.certExpired},
				[]*common.PublicKey{test.jwtKeyNotExpired, test.jwtKeyExpired},
			),
			newBundle: createBundle(
				[]*x509.Certificate{test.certNotExpired},
				[]*common.PublicKey{test.jwtKeyNotExpired},
			),
			expiration: test.currentTime,
			changed:    true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			log, _ := testlog.NewNullLogger()
			newBundle, changed, err := PruneBundle(tt.bundle, tt.expiration, log)
			require.Equal(t, tt.newBundle, newBundle)
			require.Equal(t, tt.changed, changed)
			if tt.expectedErr != "" {
				require.EqualError(t, errors.New(tt.expectedErr), err.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCommonBundleFromProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	rootCA := ca.X509Authorities()[0]
	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)

	_, expectedX509Err := x509.ParseCertificates([]byte("malformed"))
	require.Error(t, expectedX509Err)
	_, expectedJWTErr := x509.ParsePKIXPublicKey([]byte("malformed"))
	require.Error(t, expectedJWTErr)

	for _, tt := range []struct {
		name         string
		bundle       *types.Bundle
		expectBundle *common.Bundle
		expectError  string
	}{
		{
			name: "success",
			bundle: &types.Bundle{
				TrustDomain: td.Name(),
				RefreshHint: 10,
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: rootCA.Raw,
					},
				},
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: pkixBytes,
						KeyId:     "key-id-1",
						ExpiresAt: 1590514224,
					},
				},
				SequenceNumber: 42,
			},
			expectBundle: &common.Bundle{
				TrustDomainId:  td.IDString(),
				RefreshHint:    10,
				SequenceNumber: 42,
				RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes: pkixBytes,
						Kid:       "key-id-1",
						NotAfter:  1590514224,
					},
				},
			},
		},
		{
			name: "tainted authority",
			bundle: &types.Bundle{
				TrustDomain: td.Name(),
				RefreshHint: 10,
				X509Authorities: []*types.X509Certificate{
					{
						Asn1:    rootCA.Raw,
						Tainted: true,
					},
				},
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: pkixBytes,
						KeyId:     "key-id-1",
						ExpiresAt: 1590514224,
						Tainted:   true,
					},
				},
				SequenceNumber: 42,
			},
			expectBundle: &common.Bundle{
				TrustDomainId:  td.IDString(),
				RefreshHint:    10,
				SequenceNumber: 42,
				RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw, TaintedKey: true}},
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes:  pkixBytes,
						Kid:        "key-id-1",
						NotAfter:   1590514224,
						TaintedKey: true,
					},
				},
			},
		},
		{
			name: "Empty key ID",
			bundle: &types.Bundle{
				TrustDomain: td.Name(),
				RefreshHint: 10,
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: pkixBytes,
						ExpiresAt: 1590514224,
					},
				},
				SequenceNumber: 42,
			},
			expectError: "missing key ID",
		},
		{
			name:        "no bundle",
			expectError: "no bundle provided",
		},
		{
			name: "invalid trust domain",
			bundle: &types.Bundle{
				TrustDomain: "invalid TD",
			},
			expectError: `bundle has an invalid trust domain "invalid TD": trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := CommonBundleFromProto(tt.bundle)

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				require.Nil(t, bundle)
				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectBundle, bundle)
		})
	}
}

func TestSPIFFEBundleToProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	rootCA := ca.X509Authorities()[0]
	pkixBytes, err := x509.MarshalPKIXPublicKey(ca.X509Authorities()[0].PublicKey)
	require.NoError(t, err)
	bundle := spiffebundle.FromX509Authorities(td, ca.X509Authorities())
	err = bundle.AddJWTAuthority("key-id-1", ca.X509Authorities()[0].PublicKey)
	require.NoError(t, err)
	bundle.SetRefreshHint(time.Second * 10)
	bundle.SetSequenceNumber(42)
	bundleNoRefreshHint := spiffebundle.FromX509Authorities(td, ca.X509Authorities())
	bundleInvalidKey := spiffebundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{"some-key": "invalid format"})

	tests := []struct {
		name     string
		bundle   *spiffebundle.Bundle
		expProto *common.Bundle
		expErr   error
	}{
		{
			name:   "success with jwt and x509 authorities",
			bundle: bundle,
			expProto: &common.Bundle{
				TrustDomainId:  td.IDString(),
				RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
				RefreshHint:    10,
				SequenceNumber: 42,
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes: pkixBytes,
						Kid:       "key-id-1",
					},
				},
			},
		},
		{
			name:   "success spiffe bundle with no refreshHint set",
			bundle: bundleNoRefreshHint,
			expProto: &common.Bundle{
				TrustDomainId:  td.IDString(),
				RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
				RefreshHint:    0,
				SequenceNumber: 0,
			},
		},
		{
			name:   "fail with error marshalling jwt public key",
			bundle: bundleInvalidKey,
			expErr: errors.New("failed to marshal public key: x509: unsupported public key type: string"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SPIFFEBundleToProto(tt.bundle)

			if tt.expErr != nil {
				require.EqualError(t, err, tt.expErr.Error())
				return
			}
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expProto, got)
		})
	}
}

func TestSPIFFEBundleFromProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	rootCA := ca.X509Authorities()[0]
	pkixBytes, err := x509.MarshalPKIXPublicKey(ca.X509Authorities()[0].PublicKey)
	require.NoError(t, err)
	bundle := spiffebundle.FromX509Authorities(td, ca.X509Authorities())
	err = bundle.AddJWTAuthority("key-id-1", ca.X509Authorities()[0].PublicKey)
	require.NoError(t, err)
	bundle.SetRefreshHint(time.Second * 10)
	bundle.SetSequenceNumber(42)
	bundleZeroedRefreshHint := spiffebundle.FromX509Authorities(td, ca.X509Authorities())
	bundleZeroedRefreshHint.SetRefreshHint(0)
	bundleZeroedRefreshHint.SetSequenceNumber(0)

	tests := []struct {
		name      string
		proto     *common.Bundle
		expBundle *spiffebundle.Bundle
		expErr    error
	}{
		{
			name: "success with jwt and x509 authorities",
			proto: &common.Bundle{
				TrustDomainId:  td.IDString(),
				RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
				RefreshHint:    10,
				SequenceNumber: 42,
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes: pkixBytes,
						Kid:       "key-id-1",
					},
				},
			},
			expBundle: bundle,
		},
		{
			name: "success spiffe bundle with no refreshHint set",
			proto: &common.Bundle{
				TrustDomainId: td.IDString(),
				RootCas:       []*common.Certificate{{DerBytes: rootCA.Raw}},
			},
			expBundle: bundleZeroedRefreshHint,
		},
		{
			name: "fail with error parsing spiffe trust domain",
			proto: &common.Bundle{
				TrustDomainId:  "|invalid|",
				RootCas:        []*common.Certificate{{DerBytes: rootCA.Raw}},
				RefreshHint:    10,
				SequenceNumber: 42,
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes: pkixBytes,
						Kid:       "key-id-1",
					},
				},
			},
			expErr: errors.New("trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores"),
		},
		{
			name: "fail with error parsing x509 authority",
			proto: &common.Bundle{
				TrustDomainId: td.IDString(),
				RootCas:       []*common.Certificate{{DerBytes: []byte("invalid")}},
			},
			expErr: errors.New("unable to parse root CA 0: x509: malformed certificate"),
		},
		{
			name: "fail with error parsing jwt authority",
			proto: &common.Bundle{
				TrustDomainId: td.IDString(),
				RootCas:       []*common.Certificate{{DerBytes: rootCA.Raw}},
				JwtSigningKeys: []*common.PublicKey{
					{
						PkixBytes: []byte("invalid"),
					},
				},
			},
			expErr: errors.New("unable to parse JWT signing key 0: asn1: structure error: tags don't match (16 vs" +
				" {class:1 tag:9 length:110 isCompound:true}) {optional:false explicit:false application:false " +
				"private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} " +
				"publicKeyInfo @2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SPIFFEBundleFromProto(tt.proto)

			if tt.expErr != nil {
				require.EqualError(t, err, tt.expErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expBundle, got)
		})
	}
}

func TestFindX509Authorities(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")

	skID1 := x509util.SubjectKeyIDToString([]byte("ca1"))
	ca1 := &x509.Certificate{
		SubjectKeyId: []byte("ca1"),
	}
	ca2 := &x509.Certificate{
		SubjectKeyId: []byte("ca2"),
	}
	skID3 := x509util.SubjectKeyIDToString([]byte("ca3"))
	ca3 := &x509.Certificate{
		SubjectKeyId: []byte("ca3"),
	}
	testBundle := spiffebundle.FromX509Authorities(td, []*x509.Certificate{ca1, ca2, ca3})

	runTest := func(skIDs []string, expectErr string, expectResp ...*x509.Certificate) {
		found, err := FindX509Authorities(testBundle, skIDs)
		if expectErr != "" {
			require.EqualError(t, err, expectErr)
			require.Nil(t, found)
			return
		}
		require.NoError(t, err)
		require.Equal(t, expectResp, found)
	}

	runTest([]string{skID1}, "", ca1)
	runTest([]string{skID1, skID3}, "", ca1, ca3)
	runTest([]string{skID1, "foo"}, `no X.509 authority found with SubjectKeyID "foo"`)
}

func createBundle(certs []*x509.Certificate, jwtKeys []*common.PublicKey) *common.Bundle {
	bundle := BundleProtoFromRootCAs("spiffe://foo", certs)
	bundle.JwtSigningKeys = jwtKeys
	return bundle
}

func setupTest(t *testing.T) *bundleTest {
	// currentTime is a point in time between expired and not-expired certs and keys
	currentTime, err := time.Parse(time.RFC3339, "2018-02-10T01:35:00+00:00")
	require.NoError(t, err)

	certNotExpired, _, err := util.LoadSVIDFixture()
	require.NoError(t, err)

	certExpired, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	expiredKeyTime, err := time.Parse(time.RFC3339, "2018-01-10T01:35:00+00:00")
	require.NoError(t, err)

	nonExpiredKeyTime, err := time.Parse(time.RFC3339, "2018-03-10T01:35:00+00:00")
	require.NoError(t, err)

	return &bundleTest{
		currentTime:      currentTime,
		certNotExpired:   certNotExpired,
		certExpired:      certExpired,
		jwtKeyExpired:    &common.PublicKey{NotAfter: expiredKeyTime.Unix()},
		jwtKeyNotExpired: &common.PublicKey{NotAfter: nonExpiredKeyTime.Unix()},
	}
}
