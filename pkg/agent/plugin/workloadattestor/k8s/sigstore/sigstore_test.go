package sigstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
)

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
		// 		verifyFunction: func(context context.Context, ref name.Reference, co *cosign.CheckOpts) ([]cosign.SignedPayload, error) {
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
		//TODO: add test cases
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
		// TODO: Add test cases.
		// need fake oci signature objects
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
		// TODO: Add test cases.
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

func Test_getImageSubject(t *testing.T) {
	type args struct {
		verified []oci.Signature
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
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
