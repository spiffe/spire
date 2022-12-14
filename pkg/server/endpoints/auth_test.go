package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
)

var (
	testRSACertificate = fromHex("3082024b308201b4a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a38193308190300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b30190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b0500038181009d30cc402b5b50a061cbbae55358e1ed8328a9581aa938a495a1ac315a1a84663d43d32dd90bf297dfd320643892243a00bccf9c7db74020015faad3166109a276fd13c3cce10c5ceeb18782f16c04ed73bbb343778d0c1cf10fa1d8408361c94c722b9daedb4606064df4c1b33ec0d1bd42d4dbfe3d1360845c21d33be9fae7")
)

func Test_x509SVIDSource_GetX509SVID(t *testing.T) {
	ca := testca.New(t, spiffeid.RequireTrustDomainFromString("example.org"))

	serverCert, serverKey := ca.CreateX509Certificate(
		testca.WithID(spiffeid.RequireFromPath(trustDomain, "/spire/server")),
	)
	certRaw := make([][]byte, len(serverCert))
	for i, cert := range serverCert {
		certRaw[i] = cert.Raw
	}

	type fields struct {
		getter func() *tls.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		want    *x509svid.SVID
		wantErr error
	}{
		{
			name: "success, with certificate",
			fields: fields{func() *tls.Certificate {
				return &tls.Certificate{
					Certificate: certRaw,
					PrivateKey:  serverKey,
				}
			}},
			want: &x509svid.SVID{
				ID:           spiffeid.RequireFromString("spiffe://example.org/spire/server"),
				Certificates: serverCert,
				PrivateKey:   serverKey,
			},
		},
		{
			name: "error, malformed certificate",
			fields: fields{func() *tls.Certificate {
				return &tls.Certificate{
					Certificate: [][]byte{testRSACertificate[1:]},
					PrivateKey:  serverKey,
				}
			}},
			wantErr: fmt.Errorf("x509: malformed certificate"),
		},
		{
			name: "error, certificate with no uri",
			fields: fields{func() *tls.Certificate {
				return &tls.Certificate{
					Certificate: [][]byte{testRSACertificate},
					PrivateKey:  serverKey,
				}
			}},
			wantErr: fmt.Errorf("certificate contains no URI SAN"),
		},
		{
			name: "error, with empty certificates",
			fields: fields{func() *tls.Certificate {
				return &tls.Certificate{
					Certificate: [][]byte{},
					PrivateKey:  serverKey,
				}
			}},
			wantErr: fmt.Errorf("no certificates found"),
		},
		{
			name: "error, with no private key",
			fields: fields{func() *tls.Certificate {
				return &tls.Certificate{
					Certificate: [][]byte{serverCert[0].Raw},
				}
			}},
			wantErr: fmt.Errorf("agent certificate private key type <nil> is unexpectedly not a signer"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xs := newX509SVIDSource(tt.fields.getter)
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

func Test_bundleSource_GetX509BundleForTrustDomain(t *testing.T) {
	type fields struct {
		getter func(*spiffeid.TrustDomain) ([]*x509.Certificate, error)
	}
	type args struct {
		trustDomain spiffeid.TrustDomain
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *x509bundle.Bundle
		wantErr error
	}{
		{
			name: "success, with authorities",
			fields: fields{func(domain *spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				return []*x509.Certificate{&x509.Certificate{}}, nil
			}},
			args: args{
				trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			},
			want: x509bundle.FromX509Authorities(
				spiffeid.RequireTrustDomainFromString("example.org"),
				[]*x509.Certificate{&x509.Certificate{}}),
		},
		{
			name: "success, empty authorities list",
			fields: fields{func(domain *spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				return []*x509.Certificate{}, nil
			}},
			args: args{
				trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			},
			want: x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.org"), []*x509.Certificate{}),
		},
		{
			name: "error, error on getter function",
			fields: fields{func(domain *spiffeid.TrustDomain) ([]*x509.Certificate, error) {
				return nil, fmt.Errorf("some error")
			}},
			args: args{
				trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			},
			wantErr: fmt.Errorf("some error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := newBundleSource(tt.fields.getter)
			got, err := bs.GetX509BundleForTrustDomain(tt.args.trustDomain)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
