package api_test

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

func TestBundleToProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	for _, tt := range []struct {
		name         string
		bundle       *common.Bundle
		expectBundle *types.Bundle
		expectError  string
	}{
		{
			name: "success",
			bundle: &common.Bundle{
				TrustDomainId:  td.IDString(),
				RefreshHint:    10,
				SequenceNumber: 42,
				RootCas: []*common.Certificate{
					{DerBytes: []byte("cert-bytes")},
					{DerBytes: []byte("tainted-cert"), TaintedKey: true},
				},
				JwtSigningKeys: []*common.PublicKey{
					{
						Kid:       "key-id-1",
						NotAfter:  1590514224,
						PkixBytes: []byte("pkix key"),
					},
					{
						Kid:        "key-id-2",
						NotAfter:   1590514224,
						PkixBytes:  []byte("pkix key"),
						TaintedKey: true,
					},
				},
			},
			expectBundle: &types.Bundle{
				TrustDomain:    td.Name(),
				RefreshHint:    10,
				SequenceNumber: 42,
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: []byte("cert-bytes"),
					},
					{
						Asn1:    []byte("tainted-cert"),
						Tainted: true,
					},
				},
				JwtAuthorities: []*types.JWTKey{
					{

						PublicKey: []byte("pkix key"),
						KeyId:     "key-id-1",
						ExpiresAt: 1590514224,
					},
					{
						PublicKey: []byte("pkix key"),
						KeyId:     "key-id-2",
						ExpiresAt: 1590514224,
						Tainted:   true,
					},
				},
			},
		},
		{
			name:        "no bundle",
			expectError: "no bundle provided",
		},
		{
			name: "invalid trust domain",
			bundle: &common.Bundle{
				TrustDomainId: "invalid TD",
			},
			expectError: "invalid trust domain id: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := api.BundleToProto(tt.bundle)

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

func TestProtoToBundle(t *testing.T) {
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
				TrustDomain:    td.Name(),
				RefreshHint:    10,
				SequenceNumber: 42,
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
			name: "Invalid X.509 certificate bytes",
			bundle: &types.Bundle{
				TrustDomain:    td.Name(),
				RefreshHint:    10,
				SequenceNumber: 42,
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: []byte("malformed"),
					},
				},
			},
			expectError: fmt.Sprintf("unable to parse X.509 authority: %v", expectedX509Err),
		},
		{
			name: "Invalid JWT key bytes",
			bundle: &types.Bundle{
				TrustDomain:    td.Name(),
				RefreshHint:    10,
				SequenceNumber: 42,
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: []byte("malformed"),
						KeyId:     "key-id-1",
						ExpiresAt: 1590514224,
					},
				},
			},
			expectError: fmt.Sprintf("unable to parse JWT authority: %v", expectedJWTErr),
		},
		{
			name: "Empty key ID",
			bundle: &types.Bundle{
				TrustDomain:    td.Name(),
				RefreshHint:    10,
				SequenceNumber: 42,
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: pkixBytes,
						ExpiresAt: 1590514224,
					},
				},
			},
			expectError: "unable to parse JWT authority: missing key ID",
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
			expectError: "invalid trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := api.ProtoToBundle(tt.bundle)

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

func TestHashByte(t *testing.T) {
	resp := api.HashByte([]byte{1})
	require.NotEmpty(t, resp)

	resp = api.HashByte([]byte{})
	require.Equal(t, "", resp)
}

func TestFieldsFromBundleProto(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	rootCA := ca.X509Authorities()[0]
	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)

	rootCAHashed := api.HashByte(rootCA.Raw)
	pkixHashed := api.HashByte(pkixBytes)

	bundle := &types.Bundle{
		TrustDomain:    td.Name(),
		RefreshHint:    10,
		SequenceNumber: 42,
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
	}

	for _, tt := range []struct {
		name         string
		proto        *types.Bundle
		mask         *types.BundleMask
		expectFields logrus.Fields
		expectErr    string
	}{
		{
			name:  "no mask",
			proto: bundle,
			expectFields: logrus.Fields{
				"jwt_authority_expires_at.0":        int64(1590514224),
				"jwt_authority_key_id.0":            "key-id-1",
				"jwt_authority_public_key_sha256.0": pkixHashed,
				telemetry.RefreshHint:               int64(10),
				telemetry.SequenceNumber:            uint64(42),
				telemetry.TrustDomainID:             "example.org",
				"x509_authorities_asn1_sha256.0":    rootCAHashed,
			},
		},
		{
			name:  "mask all false",
			proto: bundle,
			mask:  &types.BundleMask{},
			expectFields: logrus.Fields{
				telemetry.TrustDomainID: "example.org",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fields := api.FieldsFromBundleProto(tt.proto, tt.mask)

			require.Equal(t, tt.expectFields, fields)
		})
	}
}
