package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

const (
	maximumAmountCache = 10
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
			checkOptsFunction:          DefaultCheckOpts,
		},
		skippedImages:    nil,
		allowListEnabled: false,
		subjectAllowList: nil,
		rekorURL:         url.URL{Scheme: rekor.DefaultSchemes[0], Host: rekor.DefaultHost, Path: rekor.DefaultBasePath},
		sigstorecache:    newcache,
		logger:           nil,
	}
	sigstore := New(newcache, nil)

	if sigImpObj, ok := sigstore.(*sigstoreImpl); !ok {
		t.Errorf("object type does not match")
	} else { // test each field manually since require.Equal does not work on function pointers
		if &(sigImpObj.functionHooks.verifyFunction) == &(want.functionHooks.verifyFunction) {
			t.Errorf("verify functions do not match")
		}
		if &(sigImpObj.functionHooks.fetchImageManifestFunction) == &(want.functionHooks.fetchImageManifestFunction) {
			t.Errorf("fetchImageManifest functions do not match")
		}
		if &(sigImpObj.functionHooks.checkOptsFunction) == &(want.functionHooks.checkOptsFunction) {
			t.Errorf("checkOptsFunction functions do not match")
		}
		require.Equal(t, want.skippedImages, sigImpObj.skippedImages, "skippedImages array is not empty")
		require.Equal(t, want.allowListEnabled, sigImpObj.allowListEnabled, "allowListEnabled has wrong value")
		require.Equal(t, want.subjectAllowList, sigImpObj.subjectAllowList, "subjectAllowList array is not empty")
		require.Equal(t, want.rekorURL, sigImpObj.rekorURL, "rekorURL is different from rekor default")
		require.Equal(t, want.sigstorecache, sigImpObj.sigstorecache, "sigstorecache is different from fresh object")
		require.Equal(t, want.logger, sigImpObj.logger, "new logger is not nil")
	}
}

func TestSigstoreimpl_FetchImageSignatures(t *testing.T) {
	type fields struct {
		functionBindings sigstoreFunctionBindings
		rekorURL         url.URL
	}
	type args struct {
		imageName string
	}

	defaultCheckOpts := DefaultCheckOpts(rekorDefaultURL())
	emptyURLCheckOpts := DefaultCheckOpts(url.URL{})

	tests := []struct {
		name                     string
		fields                   fields
		args                     args
		wantedFetchArguments     fetchFunctionArguments
		wantedVerifyArguments    verifyFunctionArguments
		wantedCheckOptsArguments checkOptsFunctionArguments
		want                     []oci.Signature
		wantErr                  bool
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
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    rekorDefaultURL(),
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			wantErr: false,
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
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    rekorDefaultURL(),
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 4","key3": "value 5"}}`),
				},
			},
			wantErr: false,
		},
		{
			name: "fetch image with no signature",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createVerifyFunction(nil, true, errors.New("no matching signatures 2")),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    rekorDefaultURL(),
			},
			want:      nil,
			wantErr:   true,
			wantedErr: fmt.Errorf("error verifying signature: %w", errors.New("no matching signatures 2")),
		},
		{ // TODO: check again, same as above test. should never happen, since the verify function returns an error on empty verified signature list
			name: "fetch image with no signature and no error",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding:    createVerifyFunction(nil, true, nil),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    rekorDefaultURL(),
			},
			want:      nil,
			wantErr:   false,
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
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    rekorDefaultURL(),
			},
			want:      nil,
			wantErr:   true,
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
					checkOptsBinding: createCheckOptsFunction(defaultCheckOpts),
				},
				rekorURL: rekorDefaultURL(),
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: defaultCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    rekorDefaultURL(),
			},
			want:      nil,
			wantErr:   true,
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
			wantErr:   true,
			wantedErr: fmt.Errorf("error parsing image reference: %w", errors.New("could not parse reference: invali|].url.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505")),
		},
		{
			name: "fetch image with signature, empty rekor url",
			fields: fields{
				functionBindings: sigstoreFunctionBindings{
					verifyBinding: createVerifyFunction(
						[]oci.Signature{
							signature{
								payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
							},
						}, true, nil),
					fetchBinding:     createFetchFunction(&remote.Descriptor{Manifest: []byte("sometext")}, nil),
					checkOptsBinding: createCheckOptsFunction(emptyURLCheckOpts),
				},
				rekorURL: url.URL{},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: emptyURLCheckOpts,
			},
			wantedCheckOptsArguments: checkOptsFunctionArguments{
				called: true,
				url:    url.URL{},
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			wantErr: false,
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
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:4fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments:    verifyFunctionArguments{},
			wantedCheckOptsArguments: checkOptsFunctionArguments{},
			want:                     nil,
			wantErr:                  true,
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

			if err != nil {
				if !tt.wantErr {
					t.Errorf("sigstoreImpl.FetchImageSignatures() has error, wantErr %v", tt.wantErr)
				}
				require.EqualError(t, err, tt.wantedErr.Error(), "sigstoreImpl.FetchImageSignatures() error = %v, wantedErr = %v", err, tt.wantedErr)
			} else if tt.wantErr {
				t.Errorf("sigstoreImpl.FetchImageSignatures() no error, wantErr = %v, wantedErr %v", tt.wantErr, tt.wantedErr)
			}

			require.Equal(t, tt.want, got, "sigstoreImpl.FetchImageSignatures() = %v, want %v", got, tt.want)

			require.Equal(t, tt.wantedFetchArguments, *fetchArguments, "sigstoreImpl.FetchImageSignatures() fetchArguments = %v, want %v", *fetchArguments, tt.wantedFetchArguments)

			require.Equal(t, tt.wantedCheckOptsArguments, *checkOptsArguments, "sigstoreImpl.FetchImageSignatures() checkOptsArguments = %v, want %v", *checkOptsArguments, tt.wantedCheckOptsArguments)

			require.Equal(t, tt.wantedVerifyArguments, *verifyArguments, "sigstoreImpl.FetchImageSignatures() verifyArguments = %v, want %v", *verifyArguments, tt.wantedVerifyArguments)
		})
	}
}

func TestSigstoreimpl_ExtractSelectorsFromSignatures(t *testing.T) {
	type fields struct {
		verifyFunction func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}
	type args struct {
		signatures []oci.Signature
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		containerID string
		want        []SelectorsFromSignatures
	}{
		{
			name: "extract selector from single image signature array",
			args: args{
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
					},
				},
			},
			containerID: "000000",
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
			args: args{
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
					},
				},
			},
			containerID: "111111",
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
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: nil,
					},
				},
			},
			containerID: "222222",
			want:        nil,
		},
		{
			name: "extract selector from image signature with subject certificate",
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "some reference"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"}}`),
						cert: &x509.Certificate{
							EmailAddresses: []string{
								"spirex@example.com",
								"spirex2@example.com",
							},
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
			},
			containerID: "333333",
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
			args: args{
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
			},
			containerID: "444444",
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
			name: "extract selector from empty array",
			args: args{
				signatures: []oci.Signature{},
			},
			containerID: "555555",
			want:        nil,
		},
		{
			name: "extract selector from nil array",
			args: args{
				signatures: nil,
			},
			containerID: "666666",
			want:        nil,
		},
		{
			name: "invalid payload",
			args: args{
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
			},
			containerID: "777777",
			want:        nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction: tt.fields.verifyFunction,
				},
				logger: hclog.Default(),
			}
			got := s.ExtractSelectorsFromSignatures(tt.args.signatures, tt.containerID)
			require.Equal(t, got, tt.want, "sigstoreImpl.ExtractSelectorsFromSignatures() = %v, want %v", got, tt.want)
		})
	}
}

func Test_certSubject(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "certSubject_single_email",
			args: args{
				c: &x509.Certificate{
					EmailAddresses: []string{"example@example.com"},
				},
			},
			want: "example@example.com",
		},
		{
			name: "certSubject_multiple_email",
			args: args{
				c: &x509.Certificate{
					EmailAddresses: []string{"example1@example1.com", "example2@example1.com"},
				},
			},
			want: "example1@example1.com",
		},
		{
			name: "certSubject_from_single_URI",
			args: args{
				c: &x509.Certificate{
					URIs: []*url.URL{
						{
							User: url.User("example"), Host: "example2.com"},
					},
				},
			},
			want: "example@example2.com",
		},
		{
			name: "certSubject_from_multiple_URIs",
			args: args{
				c: &x509.Certificate{
					URIs: []*url.URL{
						{
							User: url.User("example1"),
							Host: "example2.com",
						},
						{
							User: url.User("example2"),
							Host: "example2.com",
						},
					},
				},
			},
			want: "example1@example2.com",
		},
		{
			name: "certSubject_empty_certificate",
			args: args{
				c: &x509.Certificate{},
			},
			want: "",
		},
		{
			name: "certSubject_nil_certificate",
			args: args{
				c: nil,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certSubject(tt.args.c); got != tt.want {
				t.Errorf("certSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_ShouldSkipImage(t *testing.T) {
	type fields struct {
		skippedImages map[string](bool)
	}
	type args struct {
		imageID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "skipping only image in list",
			fields: fields{
				skippedImages: map[string]bool{
					"sha256:sampleimagehash": true,
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "skipping image in list",
			fields: fields{
				skippedImages: map[string]bool{
					"sha256:sampleimagehash":  true,
					"sha256:sampleimagehash2": true,
					"sha256:sampleimagehash3": true,
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash2",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "image not in list",
			fields: fields{
				skippedImages: map[string]bool{
					"sha256:sampleimagehash":  true,
					"sha256:sampleimagehash3": true,
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash2",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "empty skip list",
			fields: fields{
				skippedImages: nil,
			},
			args: args{
				imageID: "sha256:sampleimagehash",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "empty imageID",
			fields: fields{
				skippedImages: map[string]bool{
					"sha256:sampleimagehash":  true,
					"sha256:sampleimagehash2": true,
					"sha256:sampleimagehash3": true,
				},
			},
			args: args{
				imageID: "",
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := sigstoreImpl{
				skippedImages: tt.fields.skippedImages,
			}
			got, err := sigstore.ShouldSkipImage(tt.args.imageID)
			if (err != nil) != tt.wantErr {
				t.Errorf("sigstoreImpl.SkipImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, got, tt.want, "sigstoreImpl.SkipImage() = %v, want %v", got, tt.want)
		})
	}
}

func Test_getSignatureSubject(t *testing.T) {
	type args struct {
		signature oci.Signature
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "single image signature",
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			want: "spirex@example.com",
		},
		{
			name: "empty signature array",
			args: args{signature: nil},
			want: "",
		},
		{
			name: "single image signature, no payload",
			args: args{
				signature: noPayloadSignature{},
			},
			want: "",
		},
		{
			name: "single image signature, no certs",
			args: args{
				signature: &noCertSignature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			want: "",
		},
		{
			name: "single image signature,garbled subject in signature",
			args: args{
				signature: &signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "s\\\\||as\0\0aasdasd/....???/.>wd12<><,,,><{}{pirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := getSignatureSubject(tt.args.signature); got != tt.want {
				t.Errorf("getSignatureSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_AddSkippedImage(t *testing.T) {
	type fields struct {
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
		skippedImages              map[string]bool
	}
	type args struct {
		imageID []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]bool
	}{
		{
			name: "add skipped image to empty map",
			args: args{
				imageID: []string{"sha256:sampleimagehash"},
			},
			want: map[string]bool{
				"sha256:sampleimagehash": true,
			},
		},
		{
			name: "add skipped image",
			fields: fields{
				skippedImages: map[string]bool{
					"sha256:sampleimagehash1": true,
				},
			},
			args: args{
				imageID: []string{"sha256:sampleimagehash"},
			},
			want: map[string]bool{
				"sha256:sampleimagehash":  true,
				"sha256:sampleimagehash1": true,
			},
		},
		{
			name: "add a list of skipped images to empty map",
			args: args{
				imageID: []string{"sha256:sampleimagehash", "sha256:sampleimagehash1"},
			},
			want: map[string]bool{
				"sha256:sampleimagehash":  true,
				"sha256:sampleimagehash1": true,
			},
		},
		{
			name: "add a list of skipped images to a existing map",
			fields: fields{
				skippedImages: map[string]bool{
					"sha256:sampleimagehash": true,
				},
			},
			args: args{
				imageID: []string{"sha256:sampleimagehash1", "sha256:sampleimagehash2"},
			},
			want: map[string]bool{
				"sha256:sampleimagehash":  true,
				"sha256:sampleimagehash1": true,
				"sha256:sampleimagehash2": true,
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
			require.Equal(t, sigstore.skippedImages, tt.want, "sigstore.skippedImages = %v, want %v", sigstore.skippedImages, tt.want)
		})
	}
}

func TestSigstoreimpl_ClearSkipList(t *testing.T) {
	type fields struct {
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
		skippedImages              map[string]bool
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]bool
	}{
		{
			name: "clear single image in map",
			fields: fields{

				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages: map[string]bool{
					"sha256:sampleimagehash": true,
				},
			},
			want: nil,
		},
		{
			name: "clear multiple images map",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages: map[string]bool{
					"sha256:sampleimagehash":  true,
					"sha256:sampleimagehash1": true,
				},
			},
			want: nil,
		},
		{
			name: "clear on empty map",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages:              map[string]bool{},
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
			if !reflect.DeepEqual(sigstore.skippedImages, tt.want) {
				t.Errorf("sigstore.skippedImages = %v, want %v", sigstore.skippedImages, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_ValidateImage(t *testing.T) {
	type fields struct {
		verifyFunction             verifyFunctionBinding
		fetchImageManifestFunction fetchFunctionBinding
		skippedImages              map[string]bool
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
		want                  bool
		wantErr               bool
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
				called:  true,
				ref:     name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{},
			want:                  true,
			wantErr:               false,
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
				called:  true,
				ref:     name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			want:      false,
			wantErr:   true,
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
				called:  true,
				ref:     name.MustParseReference("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			want:      false,
			wantErr:   true,
			wantedErr: errors.New("manifest is empty"),
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
			got, err := sigstore.ValidateImage(tt.args.ref)

			if err != nil {
				if !tt.wantErr {
					t.Errorf("sigstoreImpl.ValidateImage() has error, wantErr %v", tt.wantErr)
				}
				require.EqualError(t, err, tt.wantedErr.Error(), "sigstoreImpl.ValidateImage() error = %v, wantedErr = %v", err, tt.wantedErr)
			} else if tt.wantErr {
				t.Errorf("sigstoreImpl.ValidateImage() no error, wantErr = %v, wantedErr %v", tt.wantErr, tt.wantedErr)
			}

			require.Equal(t, tt.want, got, "sigstoreImpl.ValidateImage() = %v, want %v", got, tt.want)
			require.Equal(t, tt.wantedFetchArguments, fetchArguments, "sigstoreImpl.ValidateImage() fetchArguments = %v, want %v", fetchArguments, tt.wantedFetchArguments)
			require.Equal(t, tt.wantedVerifyArguments, verifyArguments, "sigstoreImpl.ValidateImage() verifyArguments = %v, want %v", verifyArguments, tt.wantedVerifyArguments)
		})
	}
}

func TestSigstoreimpl_AddAllowedSubject(t *testing.T) {
	type fields struct {
		subjectAllowList map[string]bool
	}
	type args struct {
		subject string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]bool
	}{
		{
			name: "add allowed subject to nil map",
			fields: fields{
				subjectAllowList: nil,
			},
			args: args{
				subject: "spirex@example.com",
			},
			want: map[string]bool{
				"spirex@example.com": true,
			},
		},
		{
			name: "add allowed subject to empty map",
			fields: fields{
				subjectAllowList: map[string]bool{},
			},
			args: args{
				subject: "spirex@example.com",
			},
			want: map[string]bool{
				"spirex@example.com": true,
			},
		},
		{
			name: "add allowed subject to existing map",
			fields: fields{
				subjectAllowList: map[string]bool{
					"spirex1@example.com": true,
					"spirex2@example.com": true,
					"spirex3@example.com": true,
					"spirex5@example.com": true,
				},
			},
			args: args{
				subject: "spirex4@example.com",
			},
			want: map[string]bool{
				"spirex1@example.com": true,
				"spirex2@example.com": true,
				"spirex3@example.com": true,
				"spirex4@example.com": true,
				"spirex5@example.com": true,
			},
		},
		{
			name: "add existing allowed subject to existing map",
			fields: fields{
				subjectAllowList: map[string]bool{
					"spirex1@example.com": true,
					"spirex2@example.com": true,
					"spirex3@example.com": true,
					"spirex4@example.com": true,
					"spirex5@example.com": true,
				},
			},
			args: args{
				subject: "spirex4@example.com",
			},
			want: map[string]bool{
				"spirex1@example.com": true,
				"spirex2@example.com": true,
				"spirex3@example.com": true,
				"spirex4@example.com": true,
				"spirex5@example.com": true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				subjectAllowList: tt.fields.subjectAllowList,
			}
			sigstore.AddAllowedSubject(tt.args.subject)
			require.Equal(t, sigstore.subjectAllowList, tt.want, "sigstore.subjectAllowList = %v, want %v", sigstore.subjectAllowList, tt.want)
		})
	}
}

func TestSigstoreimpl_ClearAllowedSubjects(t *testing.T) {
	type fields struct {
		subjectAllowList map[string]bool
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]bool
	}{

		{
			name: "clear existing map",
			fields: fields{
				subjectAllowList: map[string]bool{
					"spirex1@example.com": true,
					"spirex2@example.com": true,
					"spirex3@example.com": true,
					"spirex4@example.com": true,
					"spirex5@example.com": true,
				},
			},
			want: nil,
		},
		{
			name: "clear empty map",
			fields: fields{
				subjectAllowList: map[string]bool{},
			},
			want: nil,
		},
		{
			name: "clear nil map",
			fields: fields{
				subjectAllowList: nil,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				subjectAllowList: tt.fields.subjectAllowList,
			}
			sigstore.ClearAllowedSubjects()
			if !reflect.DeepEqual(sigstore.subjectAllowList, tt.want) {
				t.Errorf("sigstore.subjectAllowList = %v, want %v", sigstore.subjectAllowList, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_EnableAllowSubjectList(t *testing.T) {
	type fields struct {
		allowListEnabled bool
	}
	type args struct {
		flag bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "disabling subject allow list",
			fields: fields{
				allowListEnabled: true,
			},
			args: args{
				flag: false,
			},
			want: false,
		},
		{
			name: "enabling subject allow list",
			fields: fields{
				allowListEnabled: false,
			},
			args: args{
				flag: true,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				allowListEnabled: tt.fields.allowListEnabled,
			}
			sigstore.EnableAllowSubjectList(tt.args.flag)
			if sigstore.allowListEnabled != tt.want {
				t.Errorf("sigstore.allowListEnabled = %v, want %v", sigstore.allowListEnabled, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_SelectorValuesFromSignature(t *testing.T) {
	type fields struct {
		allowListEnabled bool
		subjectAllowList map[string]bool
	}
	type args struct {
		signature oci.Signature
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		containerID string
		want        *SelectorsFromSignatures
	}{
		{
			name: "selector from signature",
			fields: fields{
				allowListEnabled: false,
				subjectAllowList: nil,
			},
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
				},
			},
			containerID: "000000",
			want: &SelectorsFromSignatures{
				Subject:        "spirex@example.com",
				Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
				LogID:          "samplelogID",
				IntegratedTime: "12345",
			},
		},
		{
			name: "selector from signature, empty subject",
			fields: fields{
				allowListEnabled: false,
				subjectAllowList: nil,
			},
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
				},
			},
			containerID: "111111",
			want:        nil,
		},
		{
			name: "selector from signature, not in allowlist",
			fields: fields{
				allowListEnabled: true,
				subjectAllowList: map[string]bool{
					"spirex2@example.com": true,
				},
			},
			args: args{
				signature: signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex1@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			containerID: "222222",
			want:        nil,
		},
		{
			name: "selector from signature, allowedlist enabled, in allowlist",
			fields: fields{
				allowListEnabled: true,
				subjectAllowList: map[string]bool{
					"spirex@example.com": true,
				},
			},
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
				},
			},
			containerID: "333333",
			want: &SelectorsFromSignatures{
				Subject:        "spirex@example.com",
				Content:        "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
				LogID:          "samplelogID",
				IntegratedTime: "12345",
			},
		},
		{
			name: "selector from signature, allowedlist enabled, in allowlist, empty content",
			fields: fields{
				allowListEnabled: true,
				subjectAllowList: map[string]bool{
					"spirex@example.com": true,
				},
			},
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
				},
			},
			containerID: "444444",
			want: &SelectorsFromSignatures{
				Subject:        "spirex@example.com",
				LogID:          "samplelogID",
				IntegratedTime: "12345"},
		},
		{
			name: "selector from signature, no bundle",
			fields: fields{
				allowListEnabled: false,
				subjectAllowList: nil,
			},
			args: args{
				signature: noBundleSignature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			containerID: "555555",
			want: &SelectorsFromSignatures{
				Subject: "spirex@example.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				allowListEnabled: tt.fields.allowListEnabled,
				subjectAllowList: tt.fields.subjectAllowList,
				logger:           hclog.Default(),
			}
			got := sigstore.SelectorValuesFromSignature(tt.args.signature, tt.containerID)
			require.Equal(t, got, tt.want, "sigstoreImpl.SelectorValuesFromSignature() = %v, want %v", got, tt.want)
		})
	}
}

func Test_getBundleSignatureContent(t *testing.T) {
	type args struct {
		bundle *bundle.RekorBundle
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "nil bundle",
			args: args{
				bundle: nil,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Bundle payload body is not a string",
			args: args{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body: 42,
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Bundle payload body is not valid base64",
			args: args{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body: "abc..........def",
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Bundle payload body has no signature content",
			args: args{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body: "ewogICAgInNwZWMiOiB7CiAgICAgICJzaWduYXR1cmUiOiB7CiAgICAgIH0KICAgIH0KfQ==",
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Bundle payload body signature content is empty",
			args: args{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body: "ewogICAgInNwZWMiOiB7CiAgICAgICAgInNpZ25hdHVyZSI6IHsKICAgICAgICAiY29udGVudCI6ICIiCiAgICAgICAgfQogICAgfQp9",
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Bundle payload body is not a valid JSON",
			args: args{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body: "ewogICJzcGVjIjosLCB7CiAgICAic2lnbmF0dXJlIjogewogICAgICAiY29udGVudCI6ICJNRVVDSVFDeWVtOEdjcjBzUEZNUDdmVFhhekNONTdOY041K01qeEp3OU9vMHgyZU0rQUlnZGdCUDk2Qk8xVGUvTmRiakhiVWViMEJVeWU2ZGVSZ1Z0UUV2NU5vNXNtQT0iCiAgICB9CiAgfQp9",
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Bundle payload body signature content is correct",
			args: args{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
						LogID:          "samplelogID",
						IntegratedTime: 12345,
					},
				},
			},
			want:    "MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getBundleSignatureContent(tt.args.bundle)
			if (err != nil) != tt.wantErr {
				t.Errorf("getBundleSignatureContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getBundleSignatureContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_AttestContainerSignatures(t *testing.T) {
	type fields struct {
		verifyFunction             verifyFunctionBinding
		fetchImageManifestFunction fetchFunctionBinding
		skippedImages              map[string]bool
		rekorURL                   url.URL
	}

	emptyCheckOpts := &cosign.CheckOpts{}

	tests := []struct {
		name                  string
		fields                fields
		status                corev1.ContainerStatus
		wantedFetchArguments  fetchFunctionArguments
		wantedVerifyArguments verifyFunctionArguments
		want                  []string
		wantErr               bool
		wantedErr             error
	}{
		{
			name: "Attest image with signature",
			fields: fields{
				verifyFunction: createVerifyFunction([]oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						bundle: &bundle.RekorBundle{
							Payload: bundle.RekorPayload{
								Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
								LogID:          "samplelogID",
								IntegratedTime: 12345,
							},
						},
					},
				}, true, nil),
				fetchImageManifestFunction: createFetchFunction(&remote.Descriptor{
					Manifest: []byte("sometext"),
				}, nil),
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-1",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "000000",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: emptyCheckOpts,
			},
			want: []string{
				"000000:image-signature-subject:spirex@example.com", "000000:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "000000:image-signature-logid:samplelogID", "000000:image-signature-integrated-time:12345", "sigstore-validation:passed",
			},
			wantErr: false,
		},
		{
			name: "Attest skipped image",
			fields: fields{
				verifyFunction: createNilVerifyFunction(),
				fetchImageManifestFunction: createFetchFunction(&remote.Descriptor{
					Manifest: []byte("sometext"),
				}, nil),
				skippedImages: map[string]bool{
					"docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505": true,
				},
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-2",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "111111",
			},
			want: []string{
				"sigstore-validation:passed",
			},
			wantErr: false,
		},
		{
			name: "Attest image with no signature",
			fields: fields{
				verifyFunction: createVerifyFunction(nil, true, fmt.Errorf("no signature found")),
				fetchImageManifestFunction: createFetchFunction(&remote.Descriptor{
					Manifest: []byte("sometext"),
				}, nil),
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-3",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "222222",
			},
			wantedFetchArguments: fetchFunctionArguments{
				called:  true,
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: nil,
			},
			wantedVerifyArguments: verifyFunctionArguments{
				called:  true,
				context: context.Background(),
				ref:     name.MustParseReference("docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"),
				options: emptyCheckOpts,
			},
			want:      nil,
			wantErr:   true,
			wantedErr: fmt.Errorf("error verifying signature: %w", errors.New("no signature found")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			co := &cosign.CheckOpts{}
			emptyCheckOptsFunction := createEmptyCheckOptsFunction(co)
			if tt.wantedVerifyArguments.options == emptyCheckOpts {
				tt.wantedVerifyArguments.options = emptyCheckOptsFunction(url.URL{})
			}
			fetchArguments := fetchFunctionArguments{}
			verifyArguments := verifyFunctionArguments{}
			sigstore := &sigstoreImpl{
				functionHooks: sigstoreFunctionHooks{
					verifyFunction:             tt.fields.verifyFunction(t, &verifyArguments),
					fetchImageManifestFunction: tt.fields.fetchImageManifestFunction(t, &fetchArguments),
					checkOptsFunction:          emptyCheckOptsFunction,
				},
				skippedImages: tt.fields.skippedImages,
				rekorURL:      tt.fields.rekorURL,
				sigstorecache: NewCache(maximumAmountCache),
				logger:        hclog.Default(),
			}
			got, err := sigstore.AttestContainerSignatures(context.Background(), &tt.status)

			if err != nil {
				if !tt.wantErr {
					t.Errorf("sigstoreImpl.AttestContainerSignatures() has error, wantErr %v", tt.wantErr)
				}
				require.EqualError(t, err, tt.wantedErr.Error(), "sigstoreImpl.AttestContainerSignatures() error = %v, wantedErr = %v", err, tt.wantedErr)
			} else if tt.wantErr {
				t.Errorf("sigstoreImpl.AttestContainerSignatures() no error, wantErr = %v, wantedErr %v", tt.wantErr, tt.wantedErr)
			}

			require.Equal(t, tt.want, got, "sigstoreImpl.AttestContainerSignatures() = %v, want %v", got, tt.want)
			require.Equal(t, tt.wantedFetchArguments, fetchArguments, "sigstoreImpl.AttestContainerSignatures() fetchArguments = %v, wantedFetchArguments = %v", fetchArguments, tt.wantedFetchArguments)
			require.Equal(t, tt.wantedVerifyArguments, verifyArguments, "sigstoreImpl.AttestContainerSignatures() verifyArguments = %v, wantedVerifyArguments = %v", verifyArguments, tt.wantedVerifyArguments)
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
		wantErr   bool
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
			wantErr: false,
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
			wantErr:   true,
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
			wantErr:   true,
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
			wantErr:   true,
			wantedErr: fmt.Errorf("host is required on rekor URL"),
		},
		{
			name: "SetRekorURL with invalid URL scheme",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "abc://invalid.url.com", // invalid scheme
			},
			want:      url.URL{},
			wantErr:   true,
			wantedErr: fmt.Errorf("invalid rekor URL Scheme %q", "abc"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &sigstoreImpl{
				rekorURL: tt.fields.rekorURL,
			}
			err := sigstore.SetRekorURL(tt.args.rekorURL)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("sigstoreImpl.SetRekorURL() has error, wantErr %v", tt.wantErr)
				}
				require.EqualError(t, err, tt.wantedErr.Error(), "sigstoreImpl.SetRekorURL() error = %v, wantedErr = %v", err, tt.wantedErr)
			} else if tt.wantErr {
				t.Errorf("sigstoreImpl.SetRekorURL() no error, wantErr = %v, wantedErr %v", tt.wantErr, tt.wantedErr)
			}
			require.Equal(t, sigstore.rekorURL, tt.want, "sigstoreImpl.SetRekorURL() = %v, want %v", sigstore.rekorURL, tt.want)
		})
	}
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

type noBundleSignature signature

func (s noBundleSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (s noBundleSignature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (s noBundleSignature) Bundle() (*bundle.RekorBundle, error) {
	return nil, fmt.Errorf("no bundle test")
}

type noCertSignature signature

func (s noCertSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (noCertSignature) Cert() (*x509.Certificate, error) {
	return nil, errors.New("no cert test")
}

type verifyFunctionArguments struct {
	called  bool
	context context.Context
	ref     name.Reference
	options *cosign.CheckOpts
}

type verifyFunctionBinding func(require.TestingT, *verifyFunctionArguments) verifyFunctionType

func createVerifyFunction(returnSignatures []oci.Signature, returnBundleVerified bool, returnError error) verifyFunctionBinding {
	bindVerifyArgumentsFunction := func(t require.TestingT, verifyArguments *verifyFunctionArguments) verifyFunctionType {
		newVerifyFunction := func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
			verifyArguments.called = true
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
			fetchArguments.called = true
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

func createCheckOptsFunction(returnCheckOpts *cosign.CheckOpts) checkOptsFunctionBinding {
	bindCheckOptsArgumentsFunction := func(t require.TestingT, checkOptsArguments *checkOptsFunctionArguments) checkOptsFunctionType {
		newCheckOptsFunction := func(url url.URL) *cosign.CheckOpts {
			checkOptsArguments.called = true
			checkOptsArguments.url = url
			return returnCheckOpts
		}
		return newCheckOptsFunction
	}
	return bindCheckOptsArgumentsFunction
}

func createNilCheckOptsFunction() checkOptsFunctionBinding {
	bindCheckOptsArgumentsFunction := func(t require.TestingT, checkOptsArguments *checkOptsFunctionArguments) checkOptsFunctionType {
		failFunction := func(url url.URL) *cosign.CheckOpts {
			require.FailNow(t, "nil check opts function should not be called")
			return nil
		}
		return failFunction
	}
	return bindCheckOptsArgumentsFunction
}

func createEmptyCheckOptsFunction(co *cosign.CheckOpts) func(url.URL) *cosign.CheckOpts {
	emptyCheckOptsFunction := func(url.URL) *cosign.CheckOpts {
		co.RekorClient = new(rekor.Rekor)
		rootCert, _, _ := GenerateRootCa()
		rootPool := x509.NewCertPool()
		rootPool.AddCert(rootCert)
		co.RootCerts = rootPool

		return co
	}
	return emptyCheckOptsFunction
}

func rekorDefaultURL() url.URL {
	return url.URL{
		Scheme: rekor.DefaultSchemes[0],
		Host:   rekor.DefaultHost,
		Path:   rekor.DefaultBasePath,
	}
}

type signature struct {
	oci.Signature

	payload []byte
	cert    *x509.Certificate
	bundle  *bundle.RekorBundle
}

type sigstoreFunctionBindings struct {
	verifyBinding    verifyFunctionBinding
	fetchBinding     fetchFunctionBinding
	checkOptsBinding checkOptsFunctionBinding
}

type checkOptsFunctionArguments struct {
	called bool
	url    url.URL
}

type checkOptsFunctionBinding func(require.TestingT, *checkOptsFunctionArguments) checkOptsFunctionType

type fetchFunctionArguments struct {
	called  bool
	ref     name.Reference
	options []remote.Option
}

type fetchFunctionBinding func(require.TestingT, *fetchFunctionArguments) fetchImageManifestFunctionType
