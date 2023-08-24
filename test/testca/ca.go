package testca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	localhostIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
)

type CA struct {
	tb     testing.TB
	td     spiffeid.TrustDomain
	parent *CA
	cert   *x509.Certificate
	key    crypto.Signer
	jwtKey crypto.Signer
	jwtKid string
}

type CertificateOption interface {
	apply(*x509.Certificate)
}

type certificateOption func(*x509.Certificate)

func (co certificateOption) apply(c *x509.Certificate) {
	co(c)
}

func New(tb testing.TB, td spiffeid.TrustDomain) *CA {
	cert, key := CreateCACertificate(tb, nil, nil)
	return &CA{
		tb:     tb,
		td:     td,
		cert:   cert,
		key:    key,
		jwtKey: testkey.NewEC256(tb),
		jwtKid: newKeyID(tb),
	}
}

func (ca *CA) ChildCA(options ...CertificateOption) *CA {
	cert, key := CreateCACertificate(ca.tb, ca.cert, ca.key, options...)
	return &CA{
		tb:     ca.tb,
		parent: ca,
		cert:   cert,
		key:    key,
		jwtKey: testkey.NewEC256(ca.tb),
		jwtKid: newKeyID(ca.tb),
	}
}

func (ca *CA) CreateX509SVID(id spiffeid.ID, options ...CertificateOption) *x509svid.SVID {
	cert, key := CreateX509SVID(ca.tb, ca.cert, ca.key, id, options...)
	return &x509svid.SVID{
		ID:           id,
		Certificates: append([]*x509.Certificate{cert}, ca.chain(false)...),
		PrivateKey:   key,
	}
}

func (ca *CA) CreateX509Certificate(options ...CertificateOption) ([]*x509.Certificate, crypto.Signer) {
	cert, key := CreateX509Certificate(ca.tb, ca.cert, ca.key, options...)
	return append([]*x509.Certificate{cert}, ca.chain(false)...), key
}

func (ca *CA) CreateJWTSVID(id spiffeid.ID, audience []string) *jwtsvid.SVID {
	claims := jwt.Claims{
		Subject:  id.String(),
		Issuer:   "FAKECA",
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(ca.jwtKey),
				KeyID: ca.jwtKid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(ca.tb, err)

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	require.NoError(ca.tb, err)

	svid, err := jwtsvid.ParseInsecure(signedToken, audience)
	require.NoError(ca.tb, err)
	return svid
}

func (ca *CA) X509Authorities() []*x509.Certificate {
	root := ca
	for root.parent != nil {
		root = root.parent
	}
	return []*x509.Certificate{root.cert}
}

func (ca *CA) JWTAuthorities() map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{
		ca.jwtKid: ca.jwtKey.Public(),
	}
}

func (ca *CA) Bundle() *spiffebundle.Bundle {
	bundle := spiffebundle.New(ca.td)
	bundle.SetX509Authorities(ca.X509Authorities())
	bundle.SetJWTAuthorities(ca.JWTAuthorities())
	return bundle
}

func (ca *CA) X509Bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.td, ca.X509Authorities())
}

func (ca *CA) JWTBundle() *jwtbundle.Bundle {
	return jwtbundle.FromJWTAuthorities(ca.td, ca.JWTAuthorities())
}

func (ca *CA) chain(includeRoot bool) []*x509.Certificate {
	chain := []*x509.Certificate{}
	next := ca
	for next != nil {
		if includeRoot || next.parent != nil {
			chain = append(chain, next.cert)
		}
		next = next.parent
	}
	return chain
}

func CreateCACertificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := newSerial(tb)
	key := testkey.NewEC256(tb)
	ski, _ := x509util.GetSubjectKeyID(key.Public())
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("CA %x", serial),
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		SubjectKeyId:          ski,
	}

	applyOptions(tmpl, options...)

	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509Certificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := newSerial(tb)
	key := testkey.NewEC256(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("X509-Certificate %x", serial),
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	applyOptions(tmpl, options...)

	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509SVID(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, id spiffeid.ID, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	serial := newSerial(tb)
	options = append(options,
		WithSerial(serial),
		WithKeyUsage(x509.KeyUsageDigitalSignature),
		WithSubject(pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		}),
		WithID(id))

	return CreateX509Certificate(tb, parent, parentKey, options...)
}

func CreateCertificate(tb testing.TB, tmpl, parent *x509.Certificate, pub, priv interface{}) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(tb, err)
	return cert
}

func CreateWebCredentials(t testing.TB) (*x509.CertPool, *tls.Certificate) {
	rootCert, rootKey := CreateCACertificate(t, nil, nil)

	childCert, childKey := CreateX509Certificate(t, rootCert, rootKey,
		WithIPAddresses(localhostIPs...))

	return util.NewCertPool(rootCert),
		&tls.Certificate{
			Certificate: [][]byte{childCert.Raw},
			PrivateKey:  childKey,
		}
}

func newSerial(tb testing.TB) *big.Int {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(tb, err)
	return new(big.Int).SetBytes(b)
}

func WithSerial(serial *big.Int) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.SerialNumber = serial
	})
}

func WithKeyUsage(keyUsage x509.KeyUsage) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.KeyUsage = keyUsage
	})
}

func WithLifetime(notBefore, notAfter time.Time) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.NotBefore = notBefore
		c.NotAfter = notAfter
	})
}

func WithIPAddresses(ips ...net.IP) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.IPAddresses = ips
	})
}

func WithID(id spiffeid.ID) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.URIs = []*url.URL{id.URL()}
	})
}

func WithSubject(subject pkix.Name) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.Subject = subject
	})
}

func applyOptions(c *x509.Certificate, options ...CertificateOption) {
	for _, opt := range options {
		opt.apply(c)
	}
}

// newKeyID returns a random id useful for identifying keys
func newKeyID(tb testing.TB) string {
	choices := make([]byte, 32)
	_, err := rand.Read(choices)
	require.NoError(tb, err)
	return keyIDFromBytes(choices)
}

func keyIDFromBytes(choices []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := new(bytes.Buffer)
	for _, choice := range choices {
		buf.WriteByte(alphabet[int(choice)%len(alphabet)])
	}
	return buf.String()
}
