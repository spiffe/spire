package endpoints

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
)

var (
	certWithoutURI, _ = pemutil.ParseCertificates([]byte(`
-----BEGIN CERTIFICATE-----                                                                                                                                                                                                                                       
MIIBFzCBvaADAgECAgEBMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBkNFUlQtQTAi                                                                                                                                                                                                  
GA8wMDAxMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjARMQ8wDQYDVQQDEwZD                                                                                                                                                                                                  
RVJULUEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6qfd5FtzLYW+p7NgjqqJu                                                                                                                                                                                                  
EAyewtzk4ypsM7PfePnL+45U+mSSypopiiyXvumOlU3uIHpnVhH+dk26KXGHeh2i                                                                                                                                                                                                  
owIwADAKBggqhkjOPQQDAgNJADBGAiEAom6HzKAkMs3wiQJUwJiSjp9q9PHaWgGh                                                                                                                                                                                                  
m7Ins/ReHk4CIQCncVaUC6i90RxiUJNfxPPMwSV9kulsj67reucS+UkBIw==                                                                                                                                                                                                      
-----END CERTIFICATE-----                                                                                                                                                                                                                                         
`))
)

func TestX509SVIDSource(t *testing.T) {
	ca := testca.New(t, spiffeid.RequireTrustDomainFromString("example.org"))

	serverCert, serverKey := ca.CreateX509Certificate(
		testca.WithID(spiffeid.RequireFromPath(trustDomain, "/spire/server")),
	)
	certRaw := make([][]byte, len(serverCert))
	for i, cert := range serverCert {
		certRaw[i] = cert.Raw
	}

	tests := []struct {
		name    string
		getter  func() svid.State
		want    *x509svid.SVID
		wantErr error
	}{
		{
			name: "success, with certificate",
			getter: func() svid.State {
				return svid.State{
					SVID: serverCert,
					Key:  serverKey,
				}
			},
			want: &x509svid.SVID{
				ID:           spiffeid.RequireFromString("spiffe://example.org/spire/server"),
				Certificates: serverCert,
				PrivateKey:   serverKey,
			},
		},
		{
			name: "error, certificate with no uri",
			getter: func() svid.State {
				return svid.State{
					SVID: certWithoutURI,
					Key:  serverKey,
				}
			},
			wantErr: errors.New("certificate contains no URI SAN"),
		},
		{
			name: "error, with empty certificates",
			getter: func() svid.State {
				return svid.State{
					SVID: []*x509.Certificate{},
					Key:  serverKey,
				}
			},
			wantErr: errors.New("no certificates found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xs := newX509SVIDSource(tt.getter)
			got, err := xs.GetX509SVID()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.Equal(t, tt.want.ID, got.ID)

				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestBundleSource(t *testing.T) {
	tests := []struct {
		name        string
		getter      func(spiffeid.TrustDomain) ([]*x509.Certificate, error)
		trustDomain spiffeid.TrustDomain
		want        *x509bundle.Bundle
		wantErr     error
	}{
		{
			name: "success, with authorities",
			getter: func(domain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				return []*x509.Certificate{&x509.Certificate{}}, nil
			},
			trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			want: x509bundle.FromX509Authorities(
				spiffeid.RequireTrustDomainFromString("example.org"),
				[]*x509.Certificate{{}}),
		},
		{
			name: "success, empty authorities list",
			getter: func(domain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				return []*x509.Certificate{}, nil
			},
			trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			want:        x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.org"), []*x509.Certificate{}),
		},
		{
			name: "error, error on getter function",
			getter: func(domain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				return nil, errors.New("some error")
			},
			trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			wantErr:     errors.New("some error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := newBundleSource(tt.getter)
			got, err := bs.GetX509BundleForTrustDomain(tt.trustDomain)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
