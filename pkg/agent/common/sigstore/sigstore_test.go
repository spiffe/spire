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

	config.SkippedImages = map[string]struct{}{
		"test-image-1": {},
		"test-image-2": {},
	}
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
	assert.NotNil(t, verifier.sigstoreFunctions.verifyImageSignatures)
	assert.NotNil(t, verifier.sigstoreFunctions.verifyImageAttestations)
	assert.NotNil(t, verifier.sigstoreFunctions.getRekorClient)
	assert.NotNil(t, verifier.sigstoreFunctions.getFulcioRoots)
	assert.NotNil(t, verifier.sigstoreFunctions.getFulcioIntermediates)
	assert.NotNil(t, verifier.sigstoreFunctions.getRekorPublicKeys)
	assert.NotNil(t, verifier.sigstoreFunctions.getCTLogPublicKeys)
}

func TestInitialize(t *testing.T) {
	verifierSetup := setupVerifier()

	ctx := context.Background()
	expectedRoots := x509.NewCertPool()
	expectedIntermediates := x509.NewCertPool()
	expectedRekorPubs := &cosign.TrustedTransparencyLogPubKeys{}
	expectedCTLogPubs := &cosign.TrustedTransparencyLogPubKeys{}
	expectedRekorClient := &rekorclient.Rekor{}

	verifierSetup.fakeGetFulcioRoots.Response.Roots = expectedRoots
	verifierSetup.fakeGetFulcioRoots.Response.Err = nil
	verifierSetup.fakeGetFulcioIntermediates.Response.Intermediates = expectedIntermediates
	verifierSetup.fakeGetFulcioIntermediates.Response.Err = nil
	verifierSetup.fakeGetRekorPubs.Response.PubKeys = expectedRekorPubs
	verifierSetup.fakeGetRekorPubs.Response.Err = nil
	verifierSetup.fakeGetCTLogPubs.Response.PubKeys = expectedCTLogPubs
	verifierSetup.fakeGetCTLogPubs.Response.Err = nil
	verifierSetup.fakeGetRekorClient.Response.Client = expectedRekorClient
	verifierSetup.fakeGetRekorClient.Response.Err = nil

	// Act
	err := verifierSetup.verifier.Init(ctx)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, expectedRoots, verifierSetup.verifier.fulcioRoots)
	assert.Equal(t, expectedIntermediates, verifierSetup.verifier.fulcioIntermediates)
	assert.Equal(t, expectedRekorPubs, verifierSetup.verifier.rekorPublicKeys)
	assert.Equal(t, expectedCTLogPubs, verifierSetup.verifier.ctLogPublicKeys)
	assert.Equal(t, expectedRekorClient, verifierSetup.verifier.rekorClient)

	assert.Equal(t, 1, verifierSetup.fakeGetFulcioRoots.CallCount)
	assert.Equal(t, 1, verifierSetup.fakeGetFulcioIntermediates.CallCount)
	assert.Equal(t, 1, verifierSetup.fakeGetRekorPubs.CallCount)
	assert.Equal(t, 1, verifierSetup.fakeGetCTLogPubs.CallCount)
	assert.Equal(t, 1, verifierSetup.fakeGetRekorClient.CallCount)
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

	tests := []struct {
		name                          string
		configureTest                 func(ctx context.Context, verifier *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, attestationsVerifyFake *fakeCosignVerifyAttestationsFn)
		expectedSelectors             []string
		expectedError                 bool
		expectedVerifyCallCount       int
		expectedAttestationsCallCount int
	}{
		{
			name: "generates selectors from verified signature, rekor bundle, and attestations",
			configureTest: func(ctx context.Context, _ *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, attestationsVerifyFake *fakeCosignVerifyAttestationsFn) {
				signature := &fakeSignature{
					payload:         createFakePayload(),
					base64Signature: "base64signature",
					cert:            createTestCert(),
					bundle:          createFakeBundle(),
				}

				signatureVerifyFake.Responses = append(signatureVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: true,
					Err:            nil,
				})
				attestationsVerifyFake.Responses = append(attestationsVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: true,
					Err:            nil,
				})
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
			expectedError:                 false,
			expectedVerifyCallCount:       1,
			expectedAttestationsCallCount: 1,
		},
		{
			name: "generates selectors from verified signature and bundle, but ignore attestations",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, _ *fakeCosignVerifyAttestationsFn) {
				verifier.config.IgnoreAttestations = true

				signature := &fakeSignature{
					payload:         createFakePayload(),
					base64Signature: "base64signature",
					cert:            createTestCert(),
					bundle:          createFakeBundle(),
				}

				signatureVerifyFake.Responses = append(signatureVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: true,
					Err:            nil,
				})
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
			expectedError:                 false,
			expectedVerifyCallCount:       1,
			expectedAttestationsCallCount: 0,
		},
		{
			name: "tlog is set to ignore, not generate selectors from bundle",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, attestationsVerifyFake *fakeCosignVerifyAttestationsFn) {
				verifier.config.IgnoreTlog = true

				signature := &fakeSignature{
					payload:         createFakePayload(),
					base64Signature: "base64signature",
					cert:            createTestCert(),
					bundle:          createFakeBundle(),
				}

				signatureVerifyFake.Responses = append(signatureVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: false,
					Err:            nil,
				})
				attestationsVerifyFake.Responses = append(attestationsVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: true,
					Err:            nil,
				})
			},
			expectedSelectors: []string{
				imageSignatureVerifiedSelector,
				imageAttestationsVerifiedSelector,
				"image-signature-subject:test-subject-san",
				"image-signature-issuer:test-issuer",
				"image-signature-value:base64signature",
			},
			expectedError:                 false,
			expectedVerifyCallCount:       1,
			expectedAttestationsCallCount: 1,
		},
		{
			name: "tlog is not ignored, verification returns bundle not verified and causes error",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, _ *fakeCosignVerifyAttestationsFn) {
				verifier.config.IgnoreTlog = false // make explicit that is not ignored

				signature := &fakeSignature{
					payload:         createFakePayload(),
					base64Signature: "base64signature",
					cert:            createTestCert(),
					bundle:          createFakeBundle(),
				}

				signatureVerifyFake.Responses = append(signatureVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: false,
					Err:            nil,
				})
			},
			expectedSelectors:             nil,
			expectedError:                 true,
			expectedVerifyCallCount:       1,
			expectedAttestationsCallCount: 0,
		},
		{
			name: "fails to verify signature",
			configureTest: func(ctx context.Context, _ *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, _ *fakeCosignVerifyAttestationsFn) {
				signatureVerifyFake.Responses = append(signatureVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     nil,
					BundleVerified: false,
					Err:            errors.New("failed to verify signature"),
				})
			},
			expectedSelectors:             nil,
			expectedError:                 true,
			expectedVerifyCallCount:       1,
			expectedAttestationsCallCount: 0,
		},
		{
			name: "fails to verify attestations",
			configureTest: func(ctx context.Context, _ *ImageVerifier, signatureVerifyFake *fakeCosignVerifySignatureFn, attestationsVerifyFake *fakeCosignVerifyAttestationsFn) {
				signature := &fakeSignature{
					payload:         createFakePayload(),
					base64Signature: "base64signature",
					cert:            createTestCert(),
					bundle:          createFakeBundle(),
				}

				signatureVerifyFake.Responses = append(signatureVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     []oci.Signature{signature},
					BundleVerified: true,
					Err:            nil,
				})
				attestationsVerifyFake.Responses = append(attestationsVerifyFake.Responses, struct {
					Signatures     []oci.Signature
					BundleVerified bool
					Err            error
				}{
					Signatures:     nil,
					BundleVerified: false,
					Err:            errors.New("failed to verify attestations"),
				})
			},
			expectedSelectors:             nil,
			expectedError:                 true,
			expectedVerifyCallCount:       1,
			expectedAttestationsCallCount: 1,
		},
		{
			name: "cache hit",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, _ *fakeCosignVerifySignatureFn, _ *fakeCosignVerifyAttestationsFn) {
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
			expectedError:                 false,
			expectedVerifyCallCount:       0,
			expectedAttestationsCallCount: 0,
		},
		{
			name: "imageID is in the skipped images list",
			configureTest: func(ctx context.Context, verifier *ImageVerifier, _ *fakeCosignVerifySignatureFn, _ *fakeCosignVerifyAttestationsFn) {
				verifier.config.SkippedImages = map[string]struct{}{imageID: {}}
			},
			expectedSelectors:             []string{},
			expectedError:                 false,
			expectedVerifyCallCount:       0,
			expectedAttestationsCallCount: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			verifierSetup := setupVerifier()
			tt.configureTest(ctx, verifierSetup.verifier, verifierSetup.fakeCosignVerifySignature, verifierSetup.fakeCosignVerifyAttestations)

			selectors, err := verifierSetup.verifier.Verify(ctx, imageID)

			assert.Equal(t, tt.expectedVerifyCallCount, verifierSetup.fakeCosignVerifySignature.CallCount)
			assert.Equal(t, tt.expectedAttestationsCallCount, verifierSetup.fakeCosignVerifyAttestations.CallCount)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedSelectors, selectors)
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

type fakeCosignVerifySignatureFn struct {
	Responses []fakeResponse
	CallCount int
}

type fakeResponse struct {
	Signatures     []oci.Signature
	BundleVerified bool
	Err            error
}

func (f *fakeCosignVerifySignatureFn) Verify(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	resp := f.Responses[f.CallCount]
	f.CallCount++
	return resp.Signatures, resp.BundleVerified, resp.Err
}

type fakeCosignVerifyAttestationsFn struct {
	Responses []struct {
		Signatures     []oci.Signature
		BundleVerified bool
		Err            error
	}
	CallCount int
}

func (f *fakeCosignVerifyAttestationsFn) Verify(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	resp := f.Responses[f.CallCount]
	f.CallCount++
	return resp.Signatures, resp.BundleVerified, resp.Err
}

type fakeGetFulcioRootsFn struct {
	Response struct {
		Roots *x509.CertPool
		Err   error
	}
	CallCount int
}

func (f *fakeGetFulcioRootsFn) Get() (*x509.CertPool, error) {
	f.CallCount++
	return f.Response.Roots, f.Response.Err
}

type fakeGetFulcioIntermediatesFn struct {
	Response struct {
		Intermediates *x509.CertPool
		Err           error
	}
	CallCount int
}

func (f *fakeGetFulcioIntermediatesFn) Get() (*x509.CertPool, error) {
	f.CallCount++
	return f.Response.Intermediates, f.Response.Err
}

type fakeGetRekorPubsFn struct {
	Response struct {
		PubKeys *cosign.TrustedTransparencyLogPubKeys
		Err     error
	}
	CallCount int
}

func (f *fakeGetRekorPubsFn) Get(_ context.Context) (*cosign.TrustedTransparencyLogPubKeys, error) {
	f.CallCount++
	return f.Response.PubKeys, f.Response.Err
}

type fakeGetCTLogPubsFn struct {
	Response struct {
		PubKeys *cosign.TrustedTransparencyLogPubKeys
		Err     error
	}
	CallCount int
}

func (f *fakeGetCTLogPubsFn) Get(_ context.Context) (*cosign.TrustedTransparencyLogPubKeys, error) {
	f.CallCount++
	return f.Response.PubKeys, f.Response.Err
}

type fakeGetRekorClientFn struct {
	Response struct {
		Client *rekorclient.Rekor
		Err    error
	}
	CallCount int
}

func (f *fakeGetRekorClientFn) Get(_ string, _ ...client.Option) (*rekorclient.Rekor, error) {
	f.CallCount++
	return f.Response.Client, f.Response.Err
}

type fakeSignature struct {
	payload         []byte
	base64Signature string
	cert            *x509.Certificate
	bundle          *bundle.RekorBundle
}

func (f *fakeSignature) Payload() ([]byte, error) {
	return f.payload, nil
}

func (f *fakeSignature) Base64Signature() (string, error) {
	return f.base64Signature, nil
}

func (f *fakeSignature) Cert() (*x509.Certificate, error) {
	return f.cert, nil
}

func (f *fakeSignature) Bundle() (*bundle.RekorBundle, error) {
	return f.bundle, nil
}

func (f *fakeSignature) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (f *fakeSignature) DiffID() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (f *fakeSignature) Compressed() (io.ReadCloser, error) {
	return nil, nil
}

func (f *fakeSignature) Uncompressed() (io.ReadCloser, error) {
	return nil, nil
}

func (f *fakeSignature) Size() (int64, error) {
	return 0, nil
}

func (f *fakeSignature) MediaType() (types.MediaType, error) {
	return "", nil
}

func (f *fakeSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (f *fakeSignature) Signature() ([]byte, error) {
	return nil, nil
}

func (f *fakeSignature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (f *fakeSignature) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	return nil, nil
}

type verifierSetup struct {
	verifier                     *ImageVerifier
	fakeCosignVerifySignature    *fakeCosignVerifySignatureFn
	fakeCosignVerifyAttestations *fakeCosignVerifyAttestationsFn
	fakeGetFulcioRoots           *fakeGetFulcioRootsFn
	fakeGetFulcioIntermediates   *fakeGetFulcioIntermediatesFn
	fakeGetRekorPubs             *fakeGetRekorPubsFn
	fakeGetCTLogPubs             *fakeGetCTLogPubsFn
	fakeGetRekorClient           *fakeGetRekorClientFn
}

func setupVerifier() verifierSetup {
	config := NewConfig()
	logger := hclog.NewNullLogger()
	config.Logger = logger
	config.RekorURL = publicRekorURL

	fakeCosignVerifySignatureFn := &fakeCosignVerifySignatureFn{}
	fakeCosignVerifyAttestationsFn := &fakeCosignVerifyAttestationsFn{}
	fakeGetFulcioRootsFn := &fakeGetFulcioRootsFn{}
	fakeGetFulcioIntermediatesFn := &fakeGetFulcioIntermediatesFn{}
	fakeGetRekorPubsFn := &fakeGetRekorPubsFn{}
	fakeGetCTLogPubsFn := &fakeGetCTLogPubsFn{}
	fakeGetRekorClientFn := &fakeGetRekorClientFn{}

	verifier := &ImageVerifier{
		config: config,
		sigstoreFunctions: sigstoreFunctions{
			verifyImageSignatures:   fakeCosignVerifySignatureFn.Verify,
			verifyImageAttestations: fakeCosignVerifyAttestationsFn.Verify,
			getRekorClient:          fakeGetRekorClientFn.Get,
			getFulcioRoots:          fakeGetFulcioRootsFn.Get,
			getFulcioIntermediates:  fakeGetFulcioIntermediatesFn.Get,
			getRekorPublicKeys:      fakeGetRekorPubsFn.Get,
			getCTLogPublicKeys:      fakeGetCTLogPubsFn.Get,
		},
	}

	return verifierSetup{
		verifier:                     verifier,
		fakeCosignVerifySignature:    fakeCosignVerifySignatureFn,
		fakeCosignVerifyAttestations: fakeCosignVerifyAttestationsFn,
		fakeGetFulcioRoots:           fakeGetFulcioRootsFn,
		fakeGetFulcioIntermediates:   fakeGetFulcioIntermediatesFn,
		fakeGetRekorPubs:             fakeGetRekorPubsFn,
		fakeGetCTLogPubs:             fakeGetCTLogPubsFn,
		fakeGetRekorClient:           fakeGetRekorClientFn,
	}
}

func createTestCert() *x509.Certificate {
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

func createFakePayload() []byte {
	signaturePayload := payload.SimpleContainerImage{
		Optional: map[string]interface{}{
			"subject": "test-subject",
		},
	}
	payloadBytes, _ := json.Marshal(signaturePayload)
	return payloadBytes
}

func createFakeBundle() *bundle.RekorBundle {
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
