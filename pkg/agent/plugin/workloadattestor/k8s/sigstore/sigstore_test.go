package sigstore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/k8s/sigstorecache"
	corev1 "k8s.io/api/core/v1"
)

const (
	maximumAmountCache = 10
)

type signature struct {
	v1.Layer

	payload []byte
	cert    *x509.Certificate
	bundle  *oci.Bundle
}

func (signature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s signature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (signature) Base64Signature() (string, error) {
	return "", nil
}

func (s signature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (signature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (s signature) Bundle() (*oci.Bundle, error) {
	return s.bundle, nil
}

func TestNew(t *testing.T) {
	newcache := sigstorecache.NewCache(maximumAmountCache)

	tests := []struct {
		name string
		want Sigstore
	}{
		{
			name: "New",
			want: &Sigstoreimpl{
				verifyFunction:             cosign.VerifyImageSignatures,
				fetchImageManifestFunction: remote.Get,
				skippedImages:              nil,
				allowListEnabled:           false,
				subjectAllowList:           map[string]bool{},
				rekorURL:                   url.URL{Scheme: rekor.DefaultSchemes[0], Host: rekor.DefaultHost, Path: rekor.DefaultBasePath},
				sigstorecache:              newcache,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(newcache); fmt.Sprintf("%v", got) != fmt.Sprintf("%v", tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_FetchImageSignatures(t *testing.T) {
	type fields struct {
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
	}
	type args struct {
		imageName string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []oci.Signature
		wantErr bool
	}{
		{
			name: "fetch image with signature",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
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
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 4","key3": "value 5"}}`),
						},
					}, true, nil
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
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
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{}, true, fmt.Errorf("no matching signatures 1")
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			want:    nil,
			wantErr: true,
		},
		{ // TODO: check again, same as above test. should never happen, since the verify function returns an error on empty verified signature list
			name: "fetch image with no signature and no error",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{}, true, fmt.Errorf("no matching signatures 2")
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				//
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature and error",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, errors.New("some error")
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature no error, bundle not verified",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
					}}, false, nil
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid image reference",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
			},
			args: args{
				imageName: "invali|].url.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature, empty rekor url",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			wantErr: false,
		},
		{
			name: "fetch image with invalid image ref",
			fields: fields{
				verifyFunction: nil,
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image@sha256:4fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := Sigstoreimpl{
				verifyFunction:             tt.fields.verifyFunction,
				fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
				sigstorecache:              sigstorecache.NewCache(maximumAmountCache),
			}
			got, err := sigstore.FetchImageSignatures(tt.args.imageName)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.FetchImageSignatures() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.FetchImageSignatures() = %v, want %v", got, tt.want)
			}
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
		want        []string
	}{
		{
			name: "extract selector from single image signature array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@example.com"}}`),
						bundle: &oci.Bundle{
							Payload: oci.BundlePayload{
								Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
								LogID:          "samplelogID",
								IntegratedTime: 12345,
							},
						},
					},
				},
			},
			containerID: "000000",
			want:        []string{"000000:image-signature-subject:spirex@example.com", "000000:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "000000:image-signature-logid:samplelogID", "000000:image-signature-integrated-time:12345"},
		},
		{
			name: "extract selector from image signature array with multiple entries",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex1@example.com","key2": "value 2","key3": "value 3"}}`),
						bundle: &oci.Bundle{
							Payload: oci.BundlePayload{
								Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
								LogID:          "samplelogID1",
								IntegratedTime: 12345,
							},
						},
					},
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex2@example.com","key2": "value 2","key3": "value 3"}}`),
						bundle: &oci.Bundle{
							Payload: oci.BundlePayload{
								Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUI9IgogICAgfQogIH0KfQo=",
								LogID:          "samplelogID2",
								IntegratedTime: 12346,
							},
						},
					},
				},
			},
			containerID: "111111",
			want:        []string{"111111:image-signature-subject:spirex1@example.com", "111111:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "111111:image-signature-logid:samplelogID1", "111111:image-signature-integrated-time:12345", "111111:image-signature-subject:spirex2@example.com", "111111:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smB=", "111111:image-signature-logid:samplelogID2", "111111:image-signature-integrated-time:12346"},
		},
		{
			name: "with invalid payload",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte{},
					},
				},
			},
			containerID: "222222",
			want:        nil,
		},
		{
			name: "extract selector from image signature with subject certificate",
			fields: fields{
				verifyFunction: nil,
			},
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
						bundle: &oci.Bundle{
							Payload: oci.BundlePayload{
								Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
								LogID:          "samplelogID",
								IntegratedTime: 12345,
							},
						},
					},
				},
			},
			containerID: "333333",
			want:        []string{"333333:image-signature-subject:spirex@example.com", "333333:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "333333:image-signature-logid:samplelogID", "333333:image-signature-integrated-time:12345"},
		},
		{
			name: "extract selector from image signature with URI certificate",
			fields: fields{
				verifyFunction: nil,
			},
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
						bundle: &oci.Bundle{
							Payload: oci.BundlePayload{
								Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
								LogID:          "samplelogID",
								IntegratedTime: 12345,
							},
						},
					},
				},
			},
			containerID: "444444",
			want:        []string{"444444:image-signature-subject:https://www.example.com/somepath1", "444444:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "444444:image-signature-logid:samplelogID", "444444:image-signature-integrated-time:12345"},
		},
		{
			name: "extract selector from empty array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{},
			},
			containerID: "555555",
			want:        nil,
		},
		{
			name: "extract selector from nil array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: nil,
			},
			containerID: "666666",
			want:        nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Sigstoreimpl{
				verifyFunction: tt.fields.verifyFunction,
			}
			if got := s.ExtractSelectorsFromSignatures(tt.args.signatures, tt.containerID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.ExtractSelectorsFromSignatures() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func Test_getOnlySubject(t *testing.T) {
// 	type args struct {
// 		payload string
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want string
// 	}{
// 		// TODO: Add test cases.
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "test1",
// 			},
// 			want: "",
// 		},
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "test2\n",
// 			},
// 			want: "",
// 		},
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "[{\"optional\":{\"Subject\":\"test3\"}}]",
// 			},
// 			want: "test3",
// 		},
// 		{
// 			name: "getOnlySubject",
// 			args: args{
// 				payload: "[{\"optional\":{\"Subject\":\"test4\"}},{\"optional\":{\"Subject\":\"test5\"}}]",
// 			},
// 			want: "test4",
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := getOnlySubject(tt.args.payload); got != tt.want {
// 				t.Errorf("getOnlySubject() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

type noCertSignature signature

func (noCertSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s noCertSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (noCertSignature) Base64Signature() (string, error) {
	return "", nil
}

func (noCertSignature) Cert() (*x509.Certificate, error) {
	return nil, errors.New("no cert test")
}

func (noCertSignature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (noCertSignature) Bundle() (*oci.Bundle, error) {
	return nil, nil
}

type noPayloadSignature signature

func (noPayloadSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (noPayloadSignature) Payload() ([]byte, error) {
	return nil, errors.New("no payload test")
}

func (noPayloadSignature) Base64Signature() (string, error) {
	return "", nil
}

func (s noPayloadSignature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (noPayloadSignature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (noPayloadSignature) Bundle() (*oci.Bundle, error) {
	return nil, nil
}

type noBundleSignature signature

func (noBundleSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s noBundleSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (noBundleSignature) Base64Signature() (string, error) {
	return "", nil
}

func (s noBundleSignature) Cert() (*x509.Certificate, error) {
	return s.cert, nil
}

func (noBundleSignature) Chain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (s noBundleSignature) Bundle() (*oci.Bundle, error) {
	return nil, fmt.Errorf("no bundle test")
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

func TestSigstoreimpl_SkipImage(t *testing.T) {
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
			sigstore := Sigstoreimpl{
				skippedImages: tt.fields.skippedImages,
			}
			got, err := sigstore.ShouldSkipImage(tt.args.imageID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.SkipImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.SkipImage() = %v, want %v", got, tt.want)
			}
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
			if got := getSignatureSubject(tt.args.signature); got != tt.want {
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
		imageID string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]bool
	}{
		{
			name: "add skipped image to empty map",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages:              nil,
			},
			args: args{
				imageID: "sha256:sampleimagehash",
			},
			want: map[string]bool{
				"sha256:sampleimagehash": true,
			},
		},
		{
			name: "add skipped image",
			fields: fields{
				verifyFunction:             nil,
				fetchImageManifestFunction: nil,
				skippedImages: map[string]bool{
					"sha256:sampleimagehash1": true,
				},
			},
			args: args{
				imageID: "sha256:sampleimagehash",
			},
			want: map[string]bool{
				"sha256:sampleimagehash":  true,
				"sha256:sampleimagehash1": true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := Sigstoreimpl{
				verifyFunction:             tt.fields.verifyFunction,
				fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
				skippedImages:              tt.fields.skippedImages,
			}
			sigstore.AddSkippedImage(tt.args.imageID)
			if !reflect.DeepEqual(sigstore.skippedImages, tt.want) {
				t.Errorf("sigstore.skippedImages = %v, want %v", sigstore.skippedImages, tt.want)
			}
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
			sigstore := &Sigstoreimpl{
				verifyFunction:             tt.fields.verifyFunction,
				fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
				skippedImages:              tt.fields.skippedImages,
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
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
		skippedImages              map[string]bool
	}
	type args struct {
		ref name.Reference
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "validate image",
			fields: fields{
				verifyFunction: nil,
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte(`sometext`),
					}, nil
				},
				skippedImages: nil,
			},
			args: args{
				ref: func(d name.Digest, err error) name.Digest { return d }(name.NewDigest("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505")),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "error on image manifest fetch",
			fields: fields{
				verifyFunction: nil,
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return nil, errors.New("fetch error")
				},
				skippedImages: nil,
			},
			args: args{
				ref: func(d name.Digest, err error) name.Digest { return d }(name.NewDigest("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505")),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "nil image manifest fetch",
			fields: fields{
				verifyFunction: nil,
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: nil,
					}, nil
				},
				skippedImages: nil,
			},
			args: args{
				ref: func(d name.Digest, err error) name.Digest { return d }(name.NewDigest("example.com/sampleimage@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505")),
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &Sigstoreimpl{
				verifyFunction:             tt.fields.verifyFunction,
				skippedImages:              tt.fields.skippedImages,
				fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
			}
			got, err := sigstore.ValidateImage(tt.args.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.ValidateImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Sigstoreimpl.ValidateImage() = %v, want %v", got, tt.want)
			}
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
			sigstore := &Sigstoreimpl{
				subjectAllowList: tt.fields.subjectAllowList,
			}
			sigstore.AddAllowedSubject(tt.args.subject)
			if !reflect.DeepEqual(sigstore.subjectAllowList, tt.want) {
				t.Errorf("sigstore.subjectAllowList = %v, want %v", sigstore.subjectAllowList, tt.want)
			}
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &Sigstoreimpl{
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
			sigstore := &Sigstoreimpl{
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
		want        []string
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
					bundle: &oci.Bundle{
						Payload: oci.BundlePayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
				},
			},
			containerID: "000000",
			want:        []string{"000000:image-signature-subject:spirex@example.com", "000000:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "000000:image-signature-logid:samplelogID", "000000:image-signature-integrated-time:12345"},
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
					bundle: &oci.Bundle{
						Payload: oci.BundlePayload{
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
					bundle: &oci.Bundle{
						Payload: oci.BundlePayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
				},
			},
			containerID: "333333",
			want:        []string{"333333:image-signature-subject:spirex@example.com", "333333:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "333333:image-signature-logid:samplelogID", "333333:image-signature-integrated-time:12345"},
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
					bundle: &oci.Bundle{
						Payload: oci.BundlePayload{
							Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiIgogICAgfQogIH0KfQ==",
							LogID:          "samplelogID",
							IntegratedTime: 12345,
						},
					},
				},
			},
			containerID: "444444",
			want:        []string{"444444:image-signature-subject:spirex@example.com", "444444:image-signature-logid:samplelogID", "444444:image-signature-integrated-time:12345"},
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
			want:        []string{"555555:image-signature-subject:spirex@example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &Sigstoreimpl{
				allowListEnabled: tt.fields.allowListEnabled,
				subjectAllowList: tt.fields.subjectAllowList,
			}
			if got := sigstore.SelectorValuesFromSignature(tt.args.signature, tt.containerID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.SelectorValuesFromSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getBundleSignatureContent(t *testing.T) {
	type args struct {
		bundle *oci.Bundle
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
				bundle: &oci.Bundle{
					Payload: oci.BundlePayload{
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
				bundle: &oci.Bundle{
					Payload: oci.BundlePayload{
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
				bundle: &oci.Bundle{
					Payload: oci.BundlePayload{
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
				bundle: &oci.Bundle{
					Payload: oci.BundlePayload{
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
				bundle: &oci.Bundle{
					Payload: oci.BundlePayload{
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
				bundle: &oci.Bundle{
					Payload: oci.BundlePayload{
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
		verifyFunction             func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
		fetchImageManifestFunction func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error)
		skippedImages              map[string]bool
		rekorURL                   url.URL
	}

	tests := []struct {
		name    string
		fields  fields
		status  corev1.ContainerStatus
		want    []string
		wantErr bool
	}{
		{
			name: "Attest image with signature",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "02c15a8d1735c65bb8ca86c716615d3c0d8beb87dc68ed88bb49192f90b184e2"},"type": "some type"},"optional": {"subject": "spirex@example.com","key2": "value 2","key3": "value 3"}}`),
							bundle: &oci.Bundle{
								Payload: oci.BundlePayload{
									Body:           "ewogICJzcGVjIjogewogICAgInNpZ25hdHVyZSI6IHsKICAgICAgImNvbnRlbnQiOiAiTUVVQ0lRQ3llbThHY3Iwc1BGTVA3ZlRYYXpDTjU3TmNONStNanhKdzlPbzB4MmVNK0FJZ2RnQlA5NkJPMVRlL05kYmpIYlVlYjBCVXllNmRlUmdWdFFFdjVObzVzbUE9IgogICAgfQogIH0KfQ==",
									LogID:          "samplelogID",
									IntegratedTime: 12345,
								},
							},
						},
					}, true, nil
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-1",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "000000",
			},
			want: []string{
				"000000:image-signature-subject:spirex@example.com", "000000:image-signature-content:MEUCIQCyem8Gcr0sPFMP7fTXazCN57NcN5+MjxJw9Oo0x2eM+AIgdgBP96BO1Te/NdbjHbUeb0BUye6deRgVtQEv5No5smA=", "000000:image-signature-logid:samplelogID", "000000:image-signature-integrated-time:12345", "000000:signature-verified:true",
			},
			wantErr: false,
		},
		{
			name: "Attest skipped image",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return nil, true, nil
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
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
				"signature-verified:true",
			},
			wantErr: false,
		},
		{
			name: "Attest image with no signature",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return nil, true, fmt.Errorf("no signature found")
				},
				fetchImageManifestFunction: func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
					return &remote.Descriptor{
						Manifest: []byte("sometext"),
					}, nil
				},
				skippedImages: nil,
			},
			status: corev1.ContainerStatus{
				Image:       "spire-agent-sigstore-3",
				ImageID:     "docker-registry.com/some/image@sha256:5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505",
				ContainerID: "222222",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &Sigstoreimpl{
				verifyFunction:             tt.fields.verifyFunction,
				fetchImageManifestFunction: tt.fields.fetchImageManifestFunction,
				skippedImages:              tt.fields.skippedImages,
				rekorURL:                   tt.fields.rekorURL,
				sigstorecache:              sigstorecache.NewCache(maximumAmountCache),
			}
			got, err := sigstore.AttestContainerSignatures(&tt.status)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.AttestContainerSignatures() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.AttestContainerSignatures() = %v, want %v", got, tt.want)
			}
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
		name    string
		fields  fields
		args    args
		want    url.URL
		wantErr bool
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
			wantErr: true,
		},
		{
			name: "SetRekorURL with invalid URL",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "http://invalid.{{}))}.url.com", // invalid url
			},
			want:    url.URL{},
			wantErr: true,
		},
		{
			name: "SetRekorURL with empty host url",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "path-no-host", // URI parser uses this as path, not host
			},
			want:    url.URL{},
			wantErr: true,
		},
		{
			name: "SetRekorURL with invalid URL scheme",
			fields: fields{
				rekorURL: url.URL{},
			},
			args: args{
				rekorURL: "abc://invalid.url.com", // invalid scheme
			},
			want:    url.URL{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := &Sigstoreimpl{
				rekorURL: tt.fields.rekorURL,
			}
			if err := sigstore.SetRekorURL(tt.args.rekorURL); (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.SetRekorURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(sigstore.rekorURL, tt.want) {
				t.Errorf("Sigstoreimpl.SetRekorURL() = %v, want %v", sigstore.rekorURL, tt.want)
			}
		})
	}
}
