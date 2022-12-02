//go:build !windows
// +build !windows

package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

const (
	maximumAmountCache = 10
)

var (
	OIDCIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

func createCertificate(template *x509.Certificate, parent *x509.Certificate, pub interface{}, priv crypto.Signer) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func GenerateRootCa() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(5 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(rootTemplate, rootTemplate, &priv.PublicKey, priv)
	return cert, priv, err
}

func TestNew(t *testing.T) {
	newcache := NewCache(maximumAmountCache)
	want := &sigstoreImpl{
		functionHooks: sigstoreFunctionHooks{
			verifyFunction:             cosign.VerifyImageSignatures,
			fetchImageManifestFunction: remote.Get,
			checkOptsFunction:          defaultCheckOptsFunction,
		},
		skippedImages:    nil,
		subjectAllowList: nil,
		rekorURL:         url.URL{},
		sigstorecache:    newcache,
		logger:           nil,
	}
	sigstore := New(newcache, nil)

	require.IsType(t, &sigstoreImpl{}, sigstore)
	sigImpObj, _ := sigstore.(*sigstoreImpl)

	// test each field manually since require.Equal does not work on function pointers
	if &(sigImpObj.functionHooks.verifyFunction) == &(want.functionHooks.verifyFunction) {
		t.Errorf("verify functions do not match")
	}
	if &(sigImpObj.functionHooks.fetchImageManifestFunction) == &(want.functionHooks.fetchImageManifestFunction) {
		t.Errorf("fetchImageManifest functions do not match")
	}
	if &(sigImpObj.functionHooks.checkOptsFunction) == &(want.functionHooks.checkOptsFunction) {
		t.Errorf("checkOptsFunction functions do not match")
	}
	require.Empty(t, sigImpObj.skippedImages, "skippedImages array is not empty")
	require.Empty(t, sigImpObj.subjectAllowList, "subjectAllowList array is not empty")
	require.Equal(t, want.rekorURL, sigImpObj.rekorURL, "rekorURL is different from rekor default")
	require.Equal(t, want.sigstorecache, sigImpObj.sigstorecache, "sigstorecache is different from fresh object")
	require.Nil(t, sigImpObj.logger, "new logger is not nil")
}

func TestSigstoreimpl_FetchImageSignatures(t *testing.T) {
	type fields struct {
		functionBindings sigstoreFunctionBindings
		rekorURL         url.URL
	}
	type args struct {
		imageName string
	}

	defaultCheckOpts, _ := defaultCheckOptsFunction(rekorDefaultURL())
	emptyURLCheckOpts, emptyError := defaultCheckOptsFunction(url.URL{})
	require.Nil(t, emptyURLCheckOpts)
	require.EqualError(t, emptyError, "rekor URL host is empty")

	tests := []struct {
		name                     string
		fields                   fields
		args                     args
		wantedFetchArguments     fetchFunctionArguments
		wantedVerifyArguments    verifyFunctionArguments
		wantedCheckOptsArguments checkOptsFunctionArguments
		want                     []oci.Signature
		wantedErr                error
	}{
		{
			name: "fetch image with signature",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction([]oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
		},
		{
			name: "fetch image with 2 signatures",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction([]oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 4","key3": "value 5"}}`),
						},
					}, true, nil),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 4","key3": "value 5"}}`),
				},
			},
		},
		{
			name: "fetch image with no signature",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createVerifyFunction(nil, true, errors.New("no matching signatures 2")),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want:      nil,
			wantedErr: fmt.Errorf("error verifying signature: %w", errors.New("no matching signatures 2")),
		},
		{ // TODO: check again, same as above test. should never happen, since the verify function returns an error on empty verified signature list
			name: "fetch image with no signature and no error",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createVerifyFunction(nil, true, nil),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want:      nil,
			wantedErr: nil,
		},
		{
			name: "fetch image with signature and error",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction([]oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, errors.New("unexpected error")),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want:      nil,
			wantedErr: fmt.Errorf("error verifying signature: %w", errors.New("unexpected error")),
		},
		{
			name: "fetch image with signature no error, bundle not verified",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction([]oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, false, nil),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want:      nil,
			wantedErr: fmt.Errorf("bundle not verified for %q", "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
		},
		{
			name: "fetch image with invalid image reference",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createNilVerifyFunction(),
					fetchBinding:     createNilFetchFunction(),
					checkOptsBinding: createNilCheckOptsFunction(),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "invali|].url.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			want:      nil,
			wantedErr: fmt.Errorf("error parsing image reference: %w", errors.New("could not parse reference: invali|].url.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505")),
		},
		{
			name: "fetch image with signature, empty rekor url",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createNilVerifyFunction(),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(emptyURLCheckOpts, emptyError),
				},
				rekorURL: url.URL{},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: url.URL{},
			},
			want:      nil,
			wantedErr: fmt.Errorf("could not create cosign check options: %w", emptyError),
		},
		{
			name: "fetch image with wrong image hash",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createNilVerifyFunction(),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createNilCheckOptsFunction(),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:4fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:4fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments:    verifyFunctionArguments{},
			wantedCheckOptsArguments: checkOptsFunctionArguments{},
			want:                     nil,
			wantedErr:                fmt.Errorf("could not validate image reference digest: %w", errors.New("digest sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505 does not match sha256:4fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetchArguments := &fetchFunctionArguments{}
			verifyArguments := &verifyFunctionArguments{}
			checkOptsArguments := &checkOptsFunctionArguments{}
			sigstore := sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction:             tt.fields.functionBindings.verifyBinding(t, verifyArguments),
					fetchImageManifestFunction: tt.fields.functionBindings.fetchBinding(t, fetchArguments),
					checkOptsFunction:          tt.fields.functionBindings.checkOptsBinding(t, checkOptsArguments),
				},
				sigstorecache: NewCache(maximumAmountCache),
				rekorURL:      tt.fields.rekorURL,
			}
			got, err := sigstore.FetchImageSignatures(context.Background(), tt.args.imageName)
			if tt.wantedErr != nil {
				require.EqualError(t, err, tt.wantedErr.Error())
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.want, got)

			require.Equal(t, tt.wantedFetchArguments, *fetchArguments)

			require.Equal(t, tt.wantedCheckOptsArguments, *checkOptsArguments)

			require.Equal(t, tt.wantedVerifyArguments, *verifyArguments)
		})
	}
}

func TestSigstoreimpl_ExtractSelectorsFromSignatures(t *testing.T) {
	tests := []struct {
		name             string
		signatures       []oci.Signature
		containerID      string
		subjectAllowList map[string]map[string]struct{}
		want             []SelectorsFromSignatures
	}{
		{
			name: "extract selector from single image signature array",
			signatures: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {"spirex@example.com": struct{}{}},
			},
			want: []SelectorsFromSignatures{
				{
					Subject:        "spirex@example.com",
					Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
					LogID:          "samplelogID",
					IntegratedTime: "12345",
				},
			},
		},
		{
			name: "extract selector from image signature array with multiple entries",
			signatures: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex1@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID1",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex1@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex2@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUI9IgogICAgfQogIH0KfQo=",
							LogID:          "samplelogID2",
							IntegratedTime: 12346,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex2@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "111111",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {"spirex1@example.com": struct{}{}, "spirex2@example.com": struct{}{}},
			},
			want: []SelectorsFromSignatures{
				{
					Subject:        "spirex1@example.com",
					Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
					LogID:          "samplelogID1",
					IntegratedTime: "12345",
				},
				{
					Subject:        "spirex2@example.com",
					Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smB=",
					LogID:          "samplelogID2",
					IntegratedTime: "12346",
				},
			},
		},
		{
			name: "with nil payload",
			signatures: []oci.Signature{
				signature{
					payload: nil,
				},
			},
			containerID: "222222",
			want:        nil,
		},
		{
			name: "extract selector from image signature with subject certificate",
			signatures: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
					cert: &x509.Certificate{
						EmailAddresses: []string{
							"spirex@example.com",
							"spirex2@example.com",
						},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
				},
			},
			containerID: "333333",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {"spirex@example.com": struct{}{}, "spirex2@example.com": struct{}{}},
			},
			want: []SelectorsFromSignatures{
				{
					Subject:        "spirex@example.com",
					Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
					LogID:          "samplelogID",
					IntegratedTime: "12345",
				},
			},
		},
		{
			name: "extract selector from image signature with URI certificate",
			signatures: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
					cert: &x509.Certificate{
						URIs: []*url.URL{
							{
								Scheme: "https",
								Host:   "www.example.com",
								Path:   "somepath1",
							},
							{
								Scheme: "https",
								Host:   "www.spirex.com",
								Path:   "somepath2",
							},
						},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
				},
			},
			containerID: "444444",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {"https://www.example.com/somepath1": struct{}{}},
			},
			want: []SelectorsFromSignatures{
				{
					Subject:        "https://www.example.com/somepath1",
					Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
					LogID:          "samplelogID",
					IntegratedTime: "12345",
				},
			},
		},
		{
			name:        "extract selector from empty array",
			signatures:  []oci.Signature{},
			containerID: "555555",
			want:        nil,
		},
		{
			name:        "extract selector from nil array",
			signatures:  nil,
			containerID: "666666",
			want:        nil,
		},
		{
			name: "invalid payload",
			signatures: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
				},
			},
			containerID: "777777",
			want:        nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := sigstoreImpl{
				logger:           hclog.Default(),
				subjectAllowList: tt.subjectAllowList,
			}
			got := s.ExtractSelectorsFromSignatures(tt.signatures, tt.containerID)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSigstoreimpl_ShouldSkipImage(t *testing.T) {
	type fields struct {
		skippedImages map[string]struct{}
	}
	type args struct {
		imageID string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      bool
		wantedErr error
	}{
		{
			name: "skipping only image in list",
			fields: fields{
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash": struct{}{},
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash",
			},
			want: true,
		},
		{
			name: "skipping image in list",
			fields: fields{
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash":  struct{}{},
					"sha256:sampleimagehash2": struct{}{},
					"sha256:sampleimagehash3": struct{}{},
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash2",
			},
			want: true,
		},
		{
			name: "image not in list",
			fields: fields{
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash":  struct{}{},
					"sha256:sampleimagehash3": struct{}{},
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash2",
			},
			want: false,
		},
		{
			name: "empty skip list",
			fields: fields{
				skippedImages: nil,
			},
			args: args{
				imageID: "sha256:sampleimagehash",
			},
			want: false,
		},
		{
			name: "empty imageID",
			fields: fields{
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash":  struct{}{},
					"sha256:sampleimagehash2": struct{}{},
					"sha256:sampleimagehash3": struct{}{},
				},
			},
			args: args{
				imageID: "",
			},
			want:      false,
			wantedErr: errors.New("image ID is empty"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := sigstoreImpl{
				skippedImages: tt.fields.skippedImages,
			}
			got, err := sigstore.ShouldSkipImage(tt.args.imageID)
			if tt.wantedErr != nil {
				require.EqualError(t, err, tt.wantedErr.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, got, tt.want)
		})
	}
}

func TestSigstoreimpl_AddSkippedImage(t *testing.T) {
	type fields struct {
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
		skippedImages              map[string]struct{}
	}
	type args struct {
		imageID []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]struct{}
	}{
		{
			name: "add skipped image to empty map",
			args: args{
				imageID: []string{"sha256:sampleimagehash"},
			},
			want: map[string]struct{}{
				"sha256:sampleimagehash": struct{}{},
			},
		},
		{
			name: "add skipped image",
			fields: fields{
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash1": struct{}{},
				},
			},
			args: args{
				imageID: []string{"sha256:sampleimagehash"},
			},
			want: map[string]struct{}{
				"sha256:sampleimagehash":  struct{}{},
				"sha256:sampleimagehash1": struct{}{},
			},
		},
		{
			name: "add a list of skipped images to empty map",
			args: args{
				imageID: []string{"sha256:sampleimagehash", "sha256:sampleimagehash1"},
			},
			want: map[string]struct{}{
				"sha256:sampleimagehash":  struct{}{},
				"sha256:sampleimagehash1": struct{}{},
			},
		},
		{
			name: "add a list of skipped images to a existing map",
			fields: fields{
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash": struct{}{},
				},
			},
			args: args{
				imageID: []string{"sha256:sampleimagehash1", "sha256:sampleimagehash2"},
			},
			want: map[string]struct{}{
				"sha256:sampleimagehash":  struct{}{},
				"sha256:sampleimagehash1": struct{}{},
				"sha256:sampleimagehash2": struct{}{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction:             tt.fields.verifyFunction,
					fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
				},
				skippedImages: tt.fields.skippedImages,
			}
			sigstore.AddSkippedImage(tt.args.imageID)
			require.Equal(t, sigstore.skippedImages, tt.want)
		})
	}
}

func TestSigstoreimpl_ClearSkipList(t *testing.T) {
	type fields struct {
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
		skippedImages              map[string]struct{}
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]struct{}
	}{
		{
			name: "clear single image in map",
			fields: fields{

				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash": struct{}{},
				},
			},
			want: nil,
		},
		{
			name: "clear multiple images map",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages: map[string]struct{}{
					"sha256:sampleimagehash":  struct{}{},
					"sha256:sampleimagehash1": struct{}{},
				},
			},
			want: nil,
		},
		{
			name: "clear on empty map",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages:              map[string]struct{}{},
			},
			want: nil,
		},
		{
			name: "clear on nil map",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages:              nil,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction:             tt.fields.verifyFunction,
					fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
				},
				skippedImages: tt.fields.skippedImages,
			}
			sigstore.ClearSkipList()
			if sigstore.skippedImages != nil {
				t.Errorf("sigstore.skippedImages = %v, want %v", sigstore.skippedImages, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_ValidateImage(t *testing.T) {
	type fields struct {
		verifyFunction             verifyFunctionBinding
		fetchImageManifestFunction fetchFunctionBinding
		skippedImages              map[string]struct{}
	}
	type args struct {
		ref name.Reference
	}
	tests := []struct {
		name                  string
		fields                fields
		args                  args
		wantedFetchArguments  fetchFunctionArguments
		wantedVerifyArguments verifyFunctionArguments
		wantedErr             error
	}{
		{
			name: "validate image",
			fields: fields{
				verifyFunction: createNilVerifyFunction(),
				fetchImageManifestFunction: createFetchFunction(&remote.Descriptor{
					Manifest: []byte(`sometext`),
				}, nil),
			},
			args: args{
				ref: name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{},
		},
		{
			name: "error on image manifest fetch",
			fields: fields{
				verifyFunction:             createNilVerifyFunction(),
				fetchImageManifestFunction: createFetchFunction(nil, errors.New("fetch error 123")),
			},
			args: args{
				ref: name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedErr: errors.New("fetch error 123"),
		},
		{
			name: "nil image manifest fetch",
			fields: fields{
				verifyFunction: createNilVerifyFunction(),
				fetchImageManifestFunction: createFetchFunction(&remote.Descriptor{
					Manifest: nil,
				}, nil),
			},
			args: args{
				ref: name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedErr: errors.New("manifest is empty"),
		},
		{
			name: "validate hash manifest",
			fields: fields{
				verifyFunction: createNilVerifyFunction(),
				fetchImageManifestFunction: createFetchFunction(&remote.Descriptor{
					Manifest: []byte("f0c62edf734ff52ee830c9eeef2ceefad94f7f089706d170f8d9dc64befb57cc"),
				}, nil),
			},
			args: args{
				ref: name.MustParseReference("example.com/sampleimage@sha256:f037cc8ec4cd38f95478773741fdecd48d721a527d19013031692edbf95fae69"),
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("example.com/sampleimage@sha256:f037cc8ec4cd38f95478773741fdecd48d721a527d19013031692edbf95fae69"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetchArguments := fetchFunctionArguments{}
			verifyArguments := verifyFunctionArguments{}
			sigstore := &sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction:             tt.fields.verifyFunction(t, &verifyArguments),
					fetchImageManifestFunction: tt.fields.fetchImageManifestFunction(t, &fetchArguments),
				},
				skippedImages: tt.fields.skippedImages,
			}

			err := sigstore.ValidateImage(tt.args.ref)
			if tt.wantedErr != nil {
				require.EqualError(t, err, tt.wantedErr.Error())
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.wantedFetchArguments, fetchArguments)
			require.Equal(t, tt.wantedVerifyArguments, verifyArguments)
		})
	}
}

func TestSigstoreimpl_AddAllowedSubject(t *testing.T) {
	tests := []struct {
		name             string
		subjectAllowList map[string]map[string]struct{}
		issuer           string
		subject          string
		want             map[string]map[string]struct{}
	}{
		{
			name:             "add allowed subject to nil map",
			subjectAllowList: nil,
			issuer:           "issuer1",
			subject:          "spirex@example.com",
			want: map[string]map[string]struct{}{
				"issuer1": {"spirex@example.com": struct{}{}},
			},
		},
		{
			name:             "add allowed subject to empty map",
			subjectAllowList: map[string]map[string]struct{}{},
			issuer:           "issuer1",
			subject:          "spirex@example.com",
			want: map[string]map[string]struct{}{
				"issuer1": {"spirex@example.com": struct{}{}},
			},
		},
		{
			name: "add allowed subject to existing map",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},
			issuer:  "issuer1",
			subject: "spirex4@example.com",
			want: map[string]map[string]struct{}{
				"issuer1": {"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},
		},
		{
			name: "add allowed subject to existing map with new issuer",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},

			issuer:  "issuer2",
			subject: "spirex4@example.com",

			want: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
				"issuer2": {
					"spirex4@example.com": struct{}{},
				},
			},
		},
		{
			name: "add existing allowed subject to existing map with new issuer",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},
			issuer:  "issuer2",
			subject: "spirex4@example.com",
			want: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
				"issuer2": {
					"spirex4@example.com": struct{}{},
				},
			},
		},
		{
			name: "add existing allowed subject to existing map with same issuer",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},
			issuer:  "issuer1",
			subject: "spirex4@example.com",
			want: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				subjectAllowList: tt.subjectAllowList,
			}
			sigstore.AddAllowedSubject(tt.issuer, tt.subject)
			require.Equal(t, tt.want, sigstore.subjectAllowList)
		})
	}
}

func TestSigstoreimpl_ClearAllowedSubjects(t *testing.T) {
	tests := []struct {
		name             string
		subjectAllowList map[string]map[string]struct{}
		want             map[string]map[string]struct{}
	}{

		{
			name: "clear existing map",
			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
			},
			want: nil,
		},
		{
			name: "clear map with multiple issuers",

			subjectAllowList: map[string]map[string]struct{}{
				"issuer1": {
					"spirex1@example.com": struct{}{},
					"spirex2@example.com": struct{}{},
					"spirex3@example.com": struct{}{},
					"spirex4@example.com": struct{}{},
					"spirex5@example.com": struct{}{},
				},
				"issuer2": {
					"spirex1@example.com": struct{}{},
					"spirex6@example.com": struct{}{},
				},
			},
			want: nil,
		},
		{
			name:             "clear empty map",
			subjectAllowList: map[string]map[string]struct{}{},
			want:             nil,
		},
		{
			name:             "clear nil map",
			subjectAllowList: nil,
			want:             nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				subjectAllowList: tt.subjectAllowList,
			}
			sigstore.ClearAllowedSubjects()
			if sigstore.subjectAllowList != nil {
				t.Errorf("sigstore.subjectAllowList = %v, want %v", sigstore.subjectAllowList, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_SelectorValuesFromSignature(t *testing.T) {
	type args struct {
		signature oci.Signature
	}
	tests := []struct {
		name             string
		args             args
		containerID      string
		subjectAllowList map[string][]string
		want             *SelectorsFromSignatures
		wantedErr        error
	}{
		{
			name: "selector from signature",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want: &SelectorsFromSignatures{
				Subject:        "spirex@example.com",
				Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
				LogID:          "samplelogID",
				IntegratedTime: "12345",
			},
		},
		{
			name: "selector from signature, empty subject",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: nil,
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID:      "111111",
			subjectAllowList: nil,
			want:             nil,
			wantedErr:        fmt.Errorf("error getting signature subject: empty subject"),
		},
		{
			name: "selector from signature, not in allowlist",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex1@example.com","key2": "value 2","key3": "value 3"}}`),
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex1@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "222222",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex2@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("subject %q not allowed for issuer %q", "spirex1@example.com", "issuer1"),
		},
		{
			name: "selector from signature, allowedlist enabled, in allowlist",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "333333",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want: &SelectorsFromSignatures{
				Subject:        "spirex@example.com",
				Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
				LogID:          "samplelogID",
				IntegratedTime: "12345",
			},
		},
		{
			name: "selector from signature, allowedlist enabled, in allowlist, empty content",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiIgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "444444",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature content: bundle payload body has no signature content"),
		},
		{
			name: "selector from signature, nil bundle",
			args: args{
				signature: nilBundleSignature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "555555",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature bundle: no bundle test"),
		},
		{
			name: "selector from signature, bundle payload body is not a string",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           42,
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature content: expected payload body to be a string but got int instead"),
		},
		{
			name: "selector from signature, bundle payload body is not valid base64",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "abc..........def",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature content: illegal base64 data at input byte 3"),
		},
		{
			name: "selector from signature, bundle payload body has no signature content",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICAgInNwZWMiOiB7CiAgICAgICJzaWduYXR1cmUiOiB7CiAgICAgIH0KICAgIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature content: bundle payload body has no signature content"),
		},
		{
			name: "selector from signature, bundle payload body signature content is empty",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICAgInNwZWMiOiB7CiAgICAgICAgInNpZ25hdHVyZSI6IHsKICAgICAgICAiY29udGVudCI6ICIiCiAgICAgICAgfQogICAgfQp9",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature content: bundle payload body has no signature content"),
		},
		{
			name: "selector from signature, bundle payload body is not a valid JSON",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					bundle: &bundle.RekorBundle{
						Payload: bundle.RekorPayload{
							Body:           "ewogICJzcGVjIjosLCB7CiAgICAic2lnbmF0dXJlIjogewogICAgICAiY29udGVudCI6ICJNRVVDSVFDeWVtOEdjcjBzUEZNUDdmVFhhekNONTdOY041K01qeEp3OU9vMHgyZU0rQUlnZGdCUDk2Qk8xVGUvTmRiakhiVWViMEJVeWU2ZGVSZ1Z0UUV2NU5vNXNtQT0iCiAgICB9CiAgfQp9",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			subjectAllowList: map[string][]string{
				"issuer1": {"spirex@example.com"},
			},
			want:      nil,
			wantedErr: fmt.Errorf("error getting signature content: failed to parse bundle body: invalid character ',' looking for beginning of value"),
		},
		{
			name: "selector from signature, empty signature array",
			args: args{
				signature: nil,
			},
			containerID: "000000",
			want:        nil,
			wantedErr:   errors.New("error getting signature subject: signature is nil"),
		},
		{
			name: "selector from signature, single image signature, no payload",
			args: args{
				signature: noPayloadSignature{},
			},
			containerID: "000000",
			want:        nil,
			wantedErr:   errors.New("error getting signature subject: no payload test"),
		},
		{
			name: "selector from signature, single image signature, no certs",
			args: args{
				signature: &noCertSignature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			containerID: "000000",
			want:        nil,
			wantedErr:   errors.New("error getting signature subject: failed to access signature certificate: no cert test"),
		},
		{
			name: "selector from signature, single image signature,garbled subject in signature",
			args: args{
				signature: &signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "s\\\\||as\0\0aasdasd/....???/.>wd12<><,,,><{}{pirex@example.com","key2": "value 2","key3": "value 3"}}`),
					cert: &x509.Certificate{
						EmailAddresses: []string{"spirex@example.com"},
						Extensions: []pkix.Extension{{
							Id:    OIDCIssuerOID,
							Value: []byte(`issuer1`),
						}},
					},
				},
			},
			containerID: "000000",
			want:        nil,
			wantedErr:   errors.New("error getting signature subject: invalid character '0' in string escape code"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				subjectAllowList: nil,
				logger:           hclog.Default(),
			}
			for issuer, subjects := range tt.subjectAllowList {
				for _, subject := range subjects {
					sigstore.AddAllowedSubject(issuer, subject)
				}
			}
			got, err := sigstore.SelectorValuesFromSignature(tt.args.signature)
			assert.Equal(t, got, tt.want)
			if tt.wantedErr != nil {
				require.EqualError(t, err, tt.wantedErr.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSigstoreimpl_AttestContainerSignatures(t *testing.T) {
	type fields struct {
		functionBindings sigstoreFunctionBindings
		skippedImages    map[string]struct{}
		rekorURL         url.URL
		subjectAllowList map[string][]string
	}

	rootCerts, err := fulcio.GetRoots()
	require.NoError(t, err)
	intermediateCerts, err := fulcio.GetIntermediates()
	require.NoError(t, err)

	defaultCheckOpts := &cosign.CheckOpts{
		RekorClient:       rekor.NewHTTPClientWithConfig(nil, rekor.DefaultTransportConfig().WithBasePath(rekorDefaultURL().Path).WithHost(rekorDefaultURL().Host)),
		RootCerts:         rootCerts,
		IntermediateCerts: intermediateCerts,
	}
	var emptyURLCheckOpts *cosign.CheckOpts
	emptyError := errors.New("rekor URL host is empty")

	tests := []struct {
		name                     string
		fields                   fields
		status                   corev1.ContainerStatus
		wantedFetchArguments     fetchFunctionArguments
		wantedVerifyArguments    verifyFunctionArguments
		wantedCheckOptsArguments checkOptsFunctionArguments
		want                     []string
		wantedErr                error
	}{
		{
			name: "Attest image with signature",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction([]oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
							bundle: &bundle.RekorBundle{
								Payload: bundle.RekorPayload{
									Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
									LogID:          "samplelogID",
									IntegratedTime: 12345,
								},
							},
							cert: &x509.Certificate{
								EmailAddresses: []string{"spirex@example.com"},
								Extensions: []pkix.Extension{{
									Id:    OIDCIssuerOID,
									Value: []byte(`issuer1`),
								}},
							},
						},
					}, true, nil),
					fetchBinding: createFetchFunction(&remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
				subjectAllowList: map[string][]string{
					"issuer1": {"spirex@example.com"},
				},
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-1",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "000000",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want: []string{
				"000000:image-signature-subject:spirex@example.com", "000000:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "000000:image-signature-logid:samplelogID", "000000:image-signature-integrated-time:12345", "sigstore-validation:passed",
			},
		},
		{
			name: "Attest skipped image",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createNilVerifyFunction(),
					fetchBinding:     createNilFetchFunction(),
					checkOptsBinding: createNilCheckOptsFunction(),
				},
				skippedImages: map[string]struct{}{
					"docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505": struct{}{},
				},
				rekorURL: rekorDefaultURL(),
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-2",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "111111",
			},
			want: []string{
				"sigstore-validation:passed",
			},
		},
		{
			name: "Attest image with no signature",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction(nil, true, fmt.Errorf("no signature found")),
					fetchBinding: createFetchFunction(&remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts, nil),
				},
				rekorURL: rekorDefaultURL(),
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-3",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "222222",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: rekorDefaultURL(),
			},
			want:      nil,
			wantedErr: fmt.Errorf("error verifying signature: %w", errors.New("no signature found")),
		},
		{
			name: "Attest image with empty rekorURL",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createNilVerifyFunction(),
					fetchBinding: createFetchFunction(&remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil),
					checkOptsBinding: createCheckOptsFunction(emptyURLCheckOpts, emptyError),
				},
				rekorURL: url.URL{},
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-3",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "222222",
			},
			wantedFetchArguments: fetchFunctionArguments{
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				url: url.URL{},
			},
			want:      nil,
			wantedErr: fmt.Errorf("could not create cosign check options: %w", emptyError),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetchArguments := fetchFunctionArguments{}
			verifyArguments := verifyFunctionArguments{}
			checkOptsArguments := checkOptsFunctionArguments{}
			sigstore := &sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction:             tt.fields.functionBindings.verifyBinding(t, &verifyArguments),
					fetchImageManifestFunction: tt.fields.functionBindings.fetchBinding(t, &fetchArguments),
					checkOptsFunction:          tt.fields.functionBindings.checkOptsBinding(t, &checkOptsArguments),
				},
				skippedImages: tt.fields.skippedImages,
				rekorURL:      tt.fields.rekorURL,
				sigstorecache: NewCache(maximumAmountCache),
				logger:        hclog.Default(),
			}

			for issuer, subjects := range tt.fields.subjectAllowList {
				for _, subject := range subjects {
					sigstore.AddAllowedSubject(issuer, subject)
				}
			}

			got, err := sigstore.AttestContainerSignatures(context.Background(), &tt.status)

			if tt.wantedErr != nil {
				require.EqualError(t, err, tt.wantedErr.Error())
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantedFetchArguments, fetchArguments)
			require.Equal(t, tt.wantedVerifyArguments, verifyArguments)
			require.Equal(t, tt.wantedCheckOptsArguments, checkOptsArguments)
		})
	}
}

func TestSigstoreimpl_SetRekorURL(t *testing.T) {
	type fields struct {
		rekorURL url.URL
	}
	type args struct {
		rekorURL string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      url.URL
		wantedErr error
	}{
		{
			name: "SetRekorURL",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "https://rekor.com",
			},
			want: url.URL{
				Scheme: "https",
				Host:   "rekor.com",
			},
		},
		{
			name: "SetRekorURL with empty url",
			fields: fields{
				rekorURL: url.URL{
					Scheme: "https",
					Host:   "non.empty.url",
				},
			},
			args: args{
				rekorURL: "",
			},
			want: url.URL{
				Scheme: "https",
				Host:   "non.empty.url",
			},
			wantedErr: fmt.Errorf("rekor URL is empty"),
		},
		{
			name: "SetRekorURL with invalid URL",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "http://invalid.{{}))}.url.com", // invalid url
			},
			want:      url.URL{},
			wantedErr: fmt.Errorf("failed parsing rekor URI: parse %q: invalid character %q in host name", "http://invalid.{{}))}.url.com", "{"),
		},
		{
			name: "SetRekorURL with empty host url",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "path-no-host", // URI parser uses this as path, not host
			},
			want:      url.URL{},
			wantedErr: fmt.Errorf("host is required on rekor URL"),
		},
		{
			name: "SetRekorURL with invalid URL scheme",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "abc://invalid.scheme.com", // invalid scheme
			},
			want:      url.URL{},
			wantedErr: fmt.Errorf("invalid rekor URL Scheme %q", "abc"),
		},
		{
			name: "SetRekorURL with empty URL scheme",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "//no.scheme.com/path", // empty scheme
			},
			want:      url.URL{},
			wantedErr: fmt.Errorf("invalid rekor URL Scheme \"\""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				rekorURL: tt.fields.rekorURL,
			}
			err := sigstore.SetRekorURL(tt.args.rekorURL)
			if tt.wantedErr != nil {
				require.EqualError(t, err, tt.wantedErr.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, sigstore.rekorURL, tt.want)
		})
	}
}

type signature struct {
	oci.Signature

	payload []byte
	cert    *x509.Certificate
	bundle  *bundle.RekorBundle
}

func (s signature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (s signature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (s signature) Bundle() (*bundle.RekorBundle, error) {
	return s.bundle, nil
}

type noPayloadSignature signature

func (noPayloadSignature) Payload() ([]byte, error) {
	return nil, errors.New("no payload test")
}

type nilBundleSignature signature

func (s nilBundleSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (s nilBundleSignature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (s nilBundleSignature) Bundle() (*bundle.RekorBundle, error) {
	return nil, fmt.Errorf("no bundle test")
}

type noCertSignature signature

func (s noCertSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (noCertSignature) Cert() (*x509.Certificate, error) {
	return nil, errors.New("no cert test")
}

func createVerifyFunction(returnSignatures []oci.Signature, returnBundleVerified bool, returnError error) verifyFunctionBinding {
	bindVerifyArgumentsFunction := func(t require.TestingT, verifyArguments *verifyFunctionArguments) verifyFunctionType {
		newVerifyFunction := func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
			verifyArguments.context = context
			verifyArguments.ref = ref
			verifyArguments.options = co
			return returnSignatures, returnBundleVerified, returnError
		}
		return newVerifyFunction
	}
	return bindVerifyArgumentsFunction
}

func createNilVerifyFunction() verifyFunctionBinding {
	bindVerifyArgumentsFunction := func(t require.TestingT, verifyArguments *verifyFunctionArguments) verifyFunctionType {
		failFunction := func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
			require.FailNow(t, "nil verify function should not be called")
			return nil, false, nil
		}
		return failFunction
	}
	return bindVerifyArgumentsFunction
}

func createFetchFunction(returnDescriptor *remote.Descriptor, returnError error) fetchFunctionBinding {
	bindFetchArgumentsFunction := func(t require.TestingT, fetchArguments *fetchFunctionArguments) fetchImageManifestFunctionType {
		newFetchFunction := func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
			fetchArguments.ref = ref
			fetchArguments.options = options
			return returnDescriptor, returnError
		}
		return newFetchFunction
	}
	return bindFetchArgumentsFunction
}

func createNilFetchFunction() fetchFunctionBinding {
	bindFetchArgumentsFunction := func(t require.TestingT, fetchArguments *fetchFunctionArguments) fetchImageManifestFunctionType {
		failFunction := func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
			require.FailNow(t, "nil fetch function should not be called")
			return nil, nil
		}
		return failFunction
	}
	return bindFetchArgumentsFunction
}

func createCheckOptsFunction(returnCheckOpts *cosign.CheckOpts, returnErr error) checkOptsFunctionBinding {
	bindCheckOptsArgumentsFunction := func(t require.TestingT, checkOptsArguments *checkOptsFunctionArguments) checkOptsFunctionType {
		newCheckOptsFunction := func(url url.URL, enforceSCT ...bool) (*cosign.CheckOpts, error) {
			checkOptsArguments.url = url
			return returnCheckOpts, returnErr
		}
		return newCheckOptsFunction
	}
	return bindCheckOptsArgumentsFunction
}

func createNilCheckOptsFunction() checkOptsFunctionBinding {
	bindCheckOptsArgumentsFunction := func(t require.TestingT, checkOptsArguments *checkOptsFunctionArguments) checkOptsFunctionType {
		failFunction := func(url url.URL, enforceSCT ...bool) (*cosign.CheckOpts, error) {
			require.FailNow(t, "nil check opts function should not be called")
			return nil, fmt.Errorf("nil check opts function should not be called")
		}
		return failFunction
	}
	return bindCheckOptsArgumentsFunction
}

func rekorDefaultURL() url.URL {
	return url.URL{
		Scheme: rekor.DefaultSchemes[0],
		Host:   rekor.DefaultHost,
		Path:   rekor.DefaultBasePath,
	}
}

type sigstoreFunctionBindings struct {
	verifyBinding    verifyFunctionBinding
	fetchBinding     fetchFunctionBinding
	checkOptsBinding checkOptsFunctionBinding
}

type checkOptsFunctionArguments struct {
	url url.URL
}

type checkOptsFunctionBinding func(require.TestingT, *checkOptsFunctionArguments) checkOptsFunctionType

type fetchFunctionArguments struct {
	ref     name.Reference
	options []remote.Option
}

type fetchFunctionBinding func(require.TestingT, *fetchFunctionArguments) fetchImageManifestFunctionType

type verifyFunctionArguments struct {
	context context.Context
	ref     name.Reference
	options *cosign.CheckOpts
}

type verifyFunctionBinding func(require.TestingT, *verifyFunctionArguments) verifyFunctionType
