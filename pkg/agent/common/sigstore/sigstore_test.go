package sigstore

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	_ "github.com/google/go-containerregistry/pkg/v1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/rekor/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewVerifier(t *testing.T) {
	config := NewConfig()
	config.Logger = hclog.NewNullLogger()
	config.IgnoreSCT = true
	config.IgnoreTlog = true
	config.IgnoreAttestations = true
	config.RekorURL = "https://rekor.test.com"
	config.RegistryCredentials = map[string]*RegistryCredential{
		"docker.io": {
			Username: "testuser",
			Password: "testpassword",
		},
		"other.io": {
			Username: "testuser",
			Password: "testpassword",
		},
	}

	config.SkippedImages = []string{"test-image-1", "test-image-2"}
	config.AllowedIdentities = map[string][]string{
		"test-issuer":    {"test-subject"},
		"test-issuer-2*": {"test-subject-2*"},
	}

	verifier := NewVerifier(config)
	require.NotNil(t, verifier)

	identityPlainValues := cosign.Identity{
		Issuer:  "test-issuer",
		Subject: "test-subject",
	}
	identityRegExp := cosign.Identity{
		IssuerRegExp:  "test-issuer-2*",
		SubjectRegExp: "test-subject-2*",
	}
	expectedIdentites := []cosign.Identity{identityPlainValues, identityRegExp}

	assert.Equal(t, config, verifier.config)
	assert.Equal(t, len(config.RegistryCredentials), len(verifier.authOptions))
	assert.ElementsMatch(t, expectedIdentites, verifier.allowedIdentities)
	assert.NotNil(t, verifier.hooks.verifySignatureFn)
	assert.NotNil(t, verifier.hooks.getRekorClientFn)
	assert.NotNil(t, verifier.hooks.trustStoreProviders.getFulcioRootsFn)
	assert.NotNil(t, verifier.hooks.trustStoreProviders.getFulcioIntermediatesFn)
	assert.NotNil(t, verifier.hooks.trustStoreProviders.getRekorPublicKeysFn)
	assert.NotNil(t, verifier.hooks.trustStoreProviders.getCTLogPublicKeysFn)
}

func TestInitialize(t *testing.T) {
	// Setup
	verifier, _, _, mockGetFulcioRootsFn, mockGetFulcioIntermediatesFn, mockGetRekorPubsFn, mockGetCTLogPubsFn, mockGetRekorClientFn := setupVerifier()

	ctx := context.Background()
	expectedRoots := x509.NewCertPool()
	expectedIntermediates := x509.NewCertPool()
	expectedRekorPubs := &cosign.TrustedTransparencyLogPubKeys{}
	expectedCTLogPubs := &cosign.TrustedTransparencyLogPubKeys{}
	expectedRekorClient := &rekorclient.Rekor{}

	mockGetFulcioRootsFn.On("Get").Return(expectedRoots, nil)
	mockGetFulcioIntermediatesFn.On("Get").Return(expectedIntermediates, nil)
	mockGetRekorPubsFn.On("Get", ctx).Return(expectedRekorPubs, nil)
	mockGetCTLogPubsFn.On("Get", ctx).Return(expectedCTLogPubs, nil)
	mockGetRekorClientFn.On("Get", verifier.config.RekorURL, mock.Anything).Return(expectedRekorClient, nil)

	// Act
	err := verifier.Init(ctx)
	require.NoError(t, err, "Init should not return an error")

	// Assert
	mockGetFulcioRootsFn.AssertExpectations(t)
	mockGetFulcioIntermediatesFn.AssertExpectations(t)
	mockGetRekorPubsFn.AssertExpectations(t)
	mockGetCTLogPubsFn.AssertExpectations(t)
	mockGetRekorClientFn.AssertExpectations(t)

	assert.Equal(t, expectedRoots, verifier.fulcioRoots)
	assert.Equal(t, expectedIntermediates, verifier.fulcioIntermediates)
	assert.Equal(t, expectedRekorPubs, verifier.rekorPublicKeys)
	assert.Equal(t, expectedCTLogPubs, verifier.ctLogPublicKeys)
	assert.Equal(t, expectedRekorClient, verifier.rekorClient)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	manifest := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest",
	}`)
	hash := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	imageID := fmt.Sprintf("test-id@%s", digest)
	imageRef, err := name.ParseReference(imageID)
	require.NoError(t, err)

	tests := []struct {
		name                    string
		configureTest           func(ctx context.Context, verifier *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn)
		expectedSelectors       []string
		expectedError           bool
		expectedFetchDescriptor bool
	}{
		{
			name: "generates selectors from verified signature, rekor bundle, and attestations",
			configureTest: func(ctx context.Context, _ *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn) {
				signature := new(MockSignature)
				signature.On("Payload").Return(createMockPayload(), nil)
				signature.On("Base64Signature").Return("base64signature", nil)
				signature.On("Cert").Return(createMockCert(), nil)
				signature.On("Bundle").Return(createMockBundle(), nil)

				signatureVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, true, nil)
				attestationsVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, true, nil)
			},
			expectedSelectors: []string{
				imageSignatureVerifiedSelector,
				imageAttestationsVerifiedSelector,
				"image-signature-subject:test-subject-san",
				"image-signature-issuer:test-issuer",
				"image-signature-value:base64signature",
				"image-signature-log-id:test-log-id",
				"image-signature-log-index:9876543210",
				"image-signature-integrated-time:1234567890",
				fmt.Sprintf("image-signature-signed-entry-timestamp:%s", base64.StdEncoding.EncodeToString([]byte("test-signed-timestamp"))),
			},
			expectedError:           false,
			expectedFetchDescriptor: true,
		},
		{
			name: "generates selectors from verified signature and bundle, but ignore attestations",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, _ *MockCosignVerifyAttestationsFn) {
				verifier.config.IgnoreAttestations = true

				signature := new(MockSignature)
				signature.On("Payload").Return(createMockPayload(), nil)
				signature.On("Base64Signature").Return("base64signature", nil)
				signature.On("Cert").Return(createMockCert(), nil)
				signature.On("Bundle").Return(createMockBundle(), nil)

				signatureVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, true, nil)
			},
			expectedSelectors: []string{
				imageSignatureVerifiedSelector,
				"image-signature-subject:test-subject-san",
				"image-signature-issuer:test-issuer",
				"image-signature-value:base64signature",
				"image-signature-log-id:test-log-id",
				"image-signature-log-index:9876543210",
				"image-signature-integrated-time:1234567890",
				fmt.Sprintf("image-signature-signed-entry-timestamp:%s", base64.StdEncoding.EncodeToString([]byte("test-signed-timestamp"))),
			},
			expectedError:           false,
			expectedFetchDescriptor: true,
		},
		{
			name: "tlog is set to ignore, not generate selectors from bundle",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn) {
				verifier.config.IgnoreTlog = true

				signature := new(MockSignature)
				signature.On("Payload").Return(createMockPayload(), nil)
				signature.On("Base64Signature").Return("base64signature", nil)
				signature.On("Cert").Return(createMockCert(), nil)
				signature.On("Bundle").Return(createMockBundle(), nil)

				// Verify returns bundleVerified=false, which should be ignored as IgnoreTlog=true
				signatureVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, false, nil)
				attestationsVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, true, nil)
			},
			expectedSelectors: []string{
				imageSignatureVerifiedSelector,
				imageAttestationsVerifiedSelector,
				"image-signature-subject:test-subject-san",
				"image-signature-issuer:test-issuer",
				"image-signature-value:base64signature",
			},
			expectedError: false,
		},
		{
			name: "tlog is not ignored, verification returns bundle not verified and causes error",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, _ *MockCosignVerifyAttestationsFn) {
				verifier.config.IgnoreTlog = false // make explicit that is not ignored

				signature := new(MockSignature)
				signature.On("Payload").Return(createMockPayload(), nil)
				signature.On("Base64Signature").Return("base64signature", nil)
				signature.On("Cert").Return(createMockCert(), nil)
				signature.On("Bundle").Return(createMockBundle(), nil)

				signatureVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, false, nil) // bundleVerified = false
			},
			expectedSelectors: nil,
			expectedError:     true,
		},
		{
			name: "fails to verify signature",
			configureTest: func(ctx context.Context, _ *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn) {
				signatureVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return(([]oci.Signature)(nil), false, errors.New("failed to verify signature"))
			},
			expectedSelectors:       nil,
			expectedError:           true,
			expectedFetchDescriptor: true,
		},
		{
			name: "fails to verify attestations",
			configureTest: func(ctx context.Context, _ *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn) {
				signature := new(MockSignature)
				signature.On("Payload").Return(createMockPayload(), nil)
				signature.On("Base64Signature").Return("base64signature", nil)
				signature.On("Cert").Return(createMockCert(), nil)
				signature.On("Bundle").Return(createMockBundle(), nil)

				signatureVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return([]oci.Signature{signature}, true, nil)
				attestationsVerifyMock.On("Verify", ctx, imageRef, mock.AnythingOfType("*cosign.CheckOpts")).Return(([]oci.Signature)(nil), false, errors.New("failed to verify attestations"))
			},
			expectedSelectors:       nil,
			expectedError:           true,
			expectedFetchDescriptor: true,
		},
		{
			name: "cache hit",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn) {
				verifier.verificationCache.Store(imageID, []string{
					imageSignatureVerifiedSelector,
					imageAttestationsVerifiedSelector,
					"image-signature-subject:some-test-subject",
					"image-signature-issuer:some-test-issuer",
					"image-signature-value:base64signature",
					"image-signature-log-id:test-log-id",
					"image-signature-integrated-time:1234567890",
					fmt.Sprintf("image-signature-signed-entry-timestamp:%s", base64.StdEncoding.EncodeToString([]byte("test-signed-timestamp"))),
				})
			},
			expectedSelectors: []string{
				imageSignatureVerifiedSelector,
				imageAttestationsVerifiedSelector,
				"image-signature-subject:some-test-subject",
				"image-signature-issuer:some-test-issuer",
				"image-signature-value:base64signature",
				"image-signature-log-id:test-log-id",
				"image-signature-integrated-time:1234567890",
				fmt.Sprintf("image-signature-signed-entry-timestamp:%s", base64.StdEncoding.EncodeToString([]byte("test-signed-timestamp"))),
			},
			expectedError:           false,
			expectedFetchDescriptor: false,
		},
		{
			name: "imageID is in the skipped images list",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyMock *MockCosignVerifySignatureFn, attestationsVerifyMock *MockCosignVerifyAttestationsFn) {
				verifier.config.SkippedImages = []string{imageID}
			},
			expectedSelectors:       []string{},
			expectedError:           false,
			expectedFetchDescriptor: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			verifier, mockVerifySignature, mockVerifyAttestations, _, _, _, _, _ := setupVerifier()
			tt.configureTest(ctx, verifier, mockVerifySignature, mockVerifyAttestations)

			selectors, err := verifier.Verify(ctx, imageID)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedSelectors, selectors)
			}

			mockVerifySignature.AssertExpectations(t)
			mockVerifyAttestations.AssertExpectations(t)
		})
	}
}

func TestProcessAllowedIdentities(t *testing.T) {
	tests := []struct {
		name              string
		allowedIdentities map[string][]string
		expected          []cosign.Identity
	}{
		{
			name: "plain strings",
			allowedIdentities: map[string][]string{
				"test-issuer": {"refs/tags/1.0.0"},
			},
			expected: []cosign.Identity{
				{
					Issuer:  "test-issuer",
					Subject: "refs/tags/1.0.0",
				},
			},
		},
		{
			name: "issuer regex, subject plain",
			allowedIdentities: map[string][]string{
				"test-issuer/*": {"refs/tags/1.0.0"},
			},
			expected: []cosign.Identity{
				{
					IssuerRegExp: "test-issuer/*",
					Subject:      "refs/tags/1.0.0",
				},
			},
		},
		{
			name: "issuer plain, subject regex",
			allowedIdentities: map[string][]string{
				"test-issuer": {"refs/tags/*"},
			},
			expected: []cosign.Identity{
				{
					Issuer:        "test-issuer",
					SubjectRegExp: "refs/tags/*",
				},
			},
		},
		{
			name: "issuers and subjects mixed patterns",
			allowedIdentities: map[string][]string{
				`test-issuer`: {`refs/(heads|tags)/release-.*`, `refs/heads/main`},
				`https://ci\.[a-zA-Z0-9-]+\.example\.com/workflows/[a-zA-Z0-9-]+`: {`refs/heads/main`, `refs/tags/v\d+\.\d+\.\d+`},
			},
			expected: []cosign.Identity{
				{
					Issuer:        `test-issuer`,
					SubjectRegExp: `refs/(heads|tags)/release-.*`,
				},
				{
					Issuer:  `test-issuer`,
					Subject: `refs/heads/main`,
				},
				{
					IssuerRegExp: `https://ci\.[a-zA-Z0-9-]+\.example\.com/workflows/[a-zA-Z0-9-]+`,
					Subject:      `refs/heads/main`,
				},
				{
					IssuerRegExp:  `https://ci\.[a-zA-Z0-9-]+\.example\.com/workflows/[a-zA-Z0-9-]+`,
					SubjectRegExp: `refs/tags/v\d+\.\d+\.\d+`,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := processAllowedIdentities(tt.allowedIdentities)
			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

type MockCosignVerifySignatureFn struct {
	mock.Mock
}

func (m *MockCosignVerifySignatureFn) Verify(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := m.Called(ctx, imageRef, checkOptions)
	return args.Get(0).([]oci.Signature), args.Bool(1), args.Error(2)
}

type MockCosignVerifyAttestationsFn struct {
	mock.Mock
}

func (m *MockCosignVerifyAttestationsFn) Verify(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	args := m.Called(ctx, imageRef, checkOptions)
	return args.Get(0).([]oci.Signature), args.Bool(1), args.Error(2)
}

type MockSignature struct {
	mock.Mock
}

func (m *MockSignature) Payload() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSignature) Base64Signature() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockSignature) Cert() (*x509.Certificate, error) {
	args := m.Called()
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockSignature) Bundle() (*bundle.RekorBundle, error) {
	args := m.Called()
	return args.Get(0).(*bundle.RekorBundle), args.Error(1)
}

func (m *MockSignature) Digest() (v1.Hash, error) {
	args := m.Called()
	return args.Get(0).(v1.Hash), args.Error(1)
}

func (m *MockSignature) DiffID() (v1.Hash, error) {
	args := m.Called()
	return args.Get(0).(v1.Hash), args.Error(1)
}

func (m *MockSignature) Compressed() (io.ReadCloser, error) {
	args := m.Called()
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockSignature) Uncompressed() (io.ReadCloser, error) {
	args := m.Called()
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockSignature) Size() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockSignature) MediaType() (types.MediaType, error) {
	args := m.Called()
	return args.Get(0).(types.MediaType), args.Error(1)
}

func (m *MockSignature) Annotations() (map[string]string, error) {
	args := m.Called()
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m *MockSignature) Signature() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSignature) Chain() ([]*x509.Certificate, error) {
	args := m.Called()
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m *MockSignature) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	args := m.Called()
	return args.Get(0).(*bundle.RFC3161Timestamp), args.Error(1)
}

type MockGetFulcioRootsFn struct {
	mock.Mock
}

func (m *MockGetFulcioRootsFn) Get() (*x509.CertPool, error) {
	args := m.Called()
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

type MockGetFulcioIntermediatesFn struct {
	mock.Mock
}

func (m *MockGetFulcioIntermediatesFn) Get() (*x509.CertPool, error) {
	args := m.Called()
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

type MockGetRekorPubsFn struct {
	mock.Mock
}

func (m *MockGetRekorPubsFn) Get(ctx context.Context) (*cosign.TrustedTransparencyLogPubKeys, error) {
	args := m.Called(ctx)
	return args.Get(0).(*cosign.TrustedTransparencyLogPubKeys), args.Error(1)
}

type MockGetCTLogPubsFn struct {
	mock.Mock
}

func (m *MockGetCTLogPubsFn) Get(ctx context.Context) (*cosign.TrustedTransparencyLogPubKeys, error) {
	args := m.Called(ctx)
	return args.Get(0).(*cosign.TrustedTransparencyLogPubKeys), args.Error(1)
}

type MockGetRekorClientFn struct {
	mock.Mock
}

func (m *MockGetRekorClientFn) Get(url string, opts ...client.Option) (*rekorclient.Rekor, error) {
	args := m.Called(url, opts)
	return args.Get(0).(*rekorclient.Rekor), args.Error(1)
}

func setupVerifier() (*ImageVerifier, *MockCosignVerifySignatureFn, *MockCosignVerifyAttestationsFn, *MockGetFulcioRootsFn, *MockGetFulcioIntermediatesFn, *MockGetRekorPubsFn, *MockGetCTLogPubsFn, *MockGetRekorClientFn) {
	config := NewConfig()
	logger := hclog.NewNullLogger()
	config.Logger = logger
	config.RekorURL = publicRekorURL

	mockCosignVerifySignatureFn := new(MockCosignVerifySignatureFn)
	mockCosignVerifyAttestationsFn := new(MockCosignVerifyAttestationsFn)
	mockGetFulcioRootsFn := new(MockGetFulcioRootsFn)
	mockGetFulcioIntermediatesFn := new(MockGetFulcioIntermediatesFn)
	mockGetRekorPubsFn := new(MockGetRekorPubsFn)
	mockGetCTLogPubsFn := new(MockGetCTLogPubsFn)
	mockGetRekorClientFn := new(MockGetRekorClientFn)

	verifier := &ImageVerifier{
		config: config,
		hooks: hooks{
			verifySignatureFn:    mockCosignVerifySignatureFn.Verify,
			verifyAttestationsFn: mockCosignVerifyAttestationsFn.Verify,
			getRekorClientFn:     mockGetRekorClientFn.Get,
			trustStoreProviders: trustStoreProviders{
				getFulcioRootsFn:         mockGetFulcioRootsFn.Get,
				getFulcioIntermediatesFn: mockGetFulcioIntermediatesFn.Get,
				getRekorPublicKeysFn:     mockGetRekorPubsFn.Get,
				getCTLogPublicKeysFn:     mockGetCTLogPubsFn.Get,
			},
		},
	}

	return verifier, mockCosignVerifySignatureFn, mockCosignVerifyAttestationsFn, mockGetFulcioRootsFn, mockGetFulcioIntermediatesFn, mockGetRekorPubsFn, mockGetCTLogPubsFn, mockGetRekorClientFn
}

func createMockCert() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test-common-name",
		},
		DNSNames: []string{"test-subject-san", "another-san"},
		Extensions: []pkix.Extension{
			{
				Id:    []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}, // OIDC issuer OID
				Value: []byte("test-issuer"),
			},
		},
	}
}

func createMockPayload() []byte {
	signaturePayload := payload.SimpleContainerImage{
		Optional: map[string]interface{}{
			"subject": "test-subject",
		},
	}
	payloadBytes, _ := json.Marshal(signaturePayload)
	return payloadBytes
}

func createMockBundle() *bundle.RekorBundle {
	signedTimestamp := "test-signed-timestamp"
	return &bundle.RekorBundle{
		SignedEntryTimestamp: []byte(signedTimestamp),
		Payload: bundle.RekorPayload{
			Body: base64.StdEncoding.EncodeToString([]byte(`{
				"apiVersion": "0.0.1",
				"kind": "bundle",
				"spec": {
					"data": {},
					"signature": {
						"content": "base64signature",
						"format": "x509",
						"publicKey": {
							"format": "pem",
							"content": "test-public-key"
						}
					}
				}
			}`)),
			LogID:          "test-log-id",
			LogIndex:       9876543210,
			IntegratedTime: 1234567890,
		},
	}
}
