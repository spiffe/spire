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
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type signature struct {
	v1.Layer

	payload []byte
	cert    *x509.Certificate
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

func (signature) Bundle() (*oci.Bundle, error) {
	return nil, nil
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		want Sigstore
	}{
		{
			name: "New",
			want: &Sigstoreimpl{verifyFunction: cosign.VerifyImageSignatures},
		},
		// { //this would break testing, but is a good example if you wan't to be sure that the test suite would test for function identity
		// 	name: "New",
		// 	want: &Sigstoreimpl{
		// 		verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
		// 			return nil, nil
		// 		},
		// 	},
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// hacky way of testing the constructor is using cosign.Verify, above is an example of how any other function would fail the test
			// it just compares the string representation of the struct, including its function pointer, which is not a good way to test the constructor, but it works
			if got := New(); fmt.Sprintf("%v", got) != fmt.Sprintf("%v", tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_FetchSignaturePayload(t *testing.T) {
	type fields struct {
		verifyFunction func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}
	type args struct {
		imageName string
		rekorURL  string
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
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
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
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
						signature{
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 4","key3": "value 5"}}`),
						},
					}, true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 4","key3": "value 5"}}`),
				},
			},
			wantErr: false,
		},
		{
			name: "fetch image with invalid rekor url",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "path-no-host", // URI parser uses this as path, not host
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid rekor host",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "http://invalid.{{}))}.url.com", // invalid url
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid rekor scheme",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "abc://invalid.url.com", // invalid scheme
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with no signature",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{}, true, fmt.Errorf("no matching signatures 1")
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{ // should never happen, since the verify function returns an error on empty verified signature list
			name: "fetch image with no signature and no error",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{}, true, fmt.Errorf("no matching signatures 2")
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature and error",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					}}, true, errors.New("some error")
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with signature no error, bundle not verified",
			fields: fields{
				verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
					return []oci.Signature{signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					}}, false, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "https://some.url/",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fetch image with invalid image reference",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				imageName: "invali|].url.com/some/image",
				rekorURL:  "https://some.url/",
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
							payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
						},
					}, true, nil
				},
			},
			args: args{
				imageName: "docker-registry.com/some/image",
				rekorURL:  "",
			},
			want: []oci.Signature{
				signature{
					payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigstore := Sigstoreimpl{
				verifyFunction: tt.fields.verifyFunction,
			}
			got, err := sigstore.FetchSignaturePayload(tt.args.imageName, tt.args.rekorURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sigstoreimpl.FetchSignaturePayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sigstoreimpl.FetchSignaturePayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigstoreimpl_ExtractselectorOfSignedImage(t *testing.T) {
	type fields struct {
		verifyFunction func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}
	type args struct {
		signatures []oci.Signature
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "extract selector from single image signature array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: "spirex@hpe.com",
		},
		{
			name: "extract selector from image signature array with multiple entries",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex1@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex2@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: "spirex1@hpe.com",
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
			want: "",
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
								"spirex@hpe.com",
								"hpe@hpe.com",
							},
						},
					},
				},
			},
			want: "spirex@hpe.com",
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
									Host:   "www.hpe.com",
									Path:   "somepath1",
								},
								{
									Scheme: "https",
									Host:   "www.spirex.com",
									Path:   "somepath2",
								},
							},
						},
					},
				},
			},
			want: "https://www.hpe.com/somepath1",
		},
		{
			name: "extract selector from empty array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: []oci.Signature{},
			},
			want: "",
		},
		{
			name: "extract selector from nil array",
			fields: fields{
				verifyFunction: nil,
			},
			args: args{
				signatures: nil,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Sigstoreimpl{
				verifyFunction: tt.fields.verifyFunction,
			}
			if got := s.ExtractselectorOfSignedImage(tt.args.signatures); got != tt.want {
				t.Errorf("Sigstoreimpl.ExtractselectorOfSignedImage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getOnlySubject(t *testing.T) {
	type args struct {
		payload string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "getOnlySubject",
			args: args{
				payload: "test1",
			},
			want: "",
		},
		{
			name: "getOnlySubject",
			args: args{
				payload: "test2\n",
			},
			want: "",
		},
		{
			name: "getOnlySubject",
			args: args{
				payload: "[{\"optional\":{\"Subject\":\"test3\"}}]",
			},
			want: "test3",
		},
		{
			name: "getOnlySubject",
			args: args{
				payload: "[{\"optional\":{\"Subject\":\"test4\"}},{\"optional\":{\"Subject\":\"test5\"}}]",
			},
			want: "test4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getOnlySubject(tt.args.payload); got != tt.want {
				t.Errorf("getOnlySubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func Test_getImageSubject(t *testing.T) {
	type args struct {
		verified []oci.Signature
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "single image signature",
			args: args{
				verified: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: "spirex@hpe.com",
		},
		{
			name: "multiple image signatures",
			args: args{
				verified: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex1@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex2@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: "spirex1@hpe.com",
		},
		{
			name: "empty signature array",
			args: args{
				verified: nil,
			},
			want: "",
		},
		{
			name: "single image signature, no payload",
			args: args{
				verified: []oci.Signature{
					noPayloadSignature{},
				},
			},
			want: "",
		},
		{
			name: "single image signature, no certs",
			args: args{
				verified: []oci.Signature{
					noCertSignature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "spirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: "",
		},
		{
			name: "single image signature,garbled subject in signature",
			args: args{
				verified: []oci.Signature{
					signature{
						payload: []byte(`{"critical": {"identity": {"docker-reference": "docker-registry.com/some/image"},"image": {"docker-manifest-digest": "some digest"},"type": "some type"},"optional": {"subject": "s\\\\||as\0\0aasdasd/....???/.>wd12<><,,,><{}{pirex@hpe.com","key2": "value 2","key3": "value 3"}}`),
					},
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getImageSubject(tt.args.verified); got != tt.want {
				t.Errorf("getImageSubject() = %v, want %v", got, tt.want)
			}
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
