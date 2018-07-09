package x509svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
)

const (
	DefaultServerCABackdate = time.Second * 10
	DefaultServerCATTL      = time.Hour
)

type ServerCAOptions struct {
	TTL          time.Duration
	Backdate     time.Duration
	SerialNumber SerialNumber
}

type ServerCA struct {
	keypair      Keypair
	serialNumber SerialNumber
	trustDomain  string
	options      ServerCAOptions
}

func NewServerCA(keypair Keypair, trustDomain string, options ServerCAOptions) *ServerCA {
	if options.TTL <= 0 {
		options.TTL = DefaultServerCATTL
	}
	if options.Backdate <= 0 {
		options.Backdate = DefaultServerCABackdate
	}
	if options.SerialNumber == nil {
		options.SerialNumber = NewSerialNumber()
	}

	return &ServerCA{
		keypair:     keypair,
		trustDomain: trustDomain,
		options:     options,
	}
}

func (ca *ServerCA) SignCSR(ctx context.Context, csrDER []byte, ttl time.Duration) (*x509.Certificate, error) {
	csr, err := ParseAndValidateCSR(csrDER, idutil.AllowAnyInTrustDomain(ca.trustDomain))
	if err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyId(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	if ttl <= 0 {
		ttl = ca.options.TTL
	}

	notBefore := now.Add(-ca.options.Backdate)
	notAfter := now.Add(ttl)

	caCert, err := ca.keypair.GetCertificate(ctx)
	if err != nil {
		return nil, err
	}
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}

	serialNumber, err := ca.options.SerialNumber.NextNumber(ctx)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:    serialNumber,
		ExtraExtensions: csr.Extensions,
		Subject:         csr.Subject,
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		SubjectKeyId:    keyID,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := ca.keypair.CreateCertificate(ctx, template, csr.PublicKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

type ServerCACSROptions struct {
	Subject pkix.Name
}

func GenerateServerCACSR(key *ecdsa.PrivateKey, trustDomain string, options ServerCACSROptions) ([]byte, error) {
	spiffeID := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
	}

	uriSans, err := uri.MarshalUriSANs([]string{spiffeID.String()})
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		Subject:            options.Subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       uri.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: false,
			},
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func ParseAndValidateServerCACertificate(certDER []byte, trustDomain string) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse server CA certificate: %v", err)
	}

	if err := ValidateServerCACertificate(cert, trustDomain); err != nil {
		return nil, err
	}

	return cert, nil
}

func ValidateServerCACertificate(cert *x509.Certificate, trustDomain string) error {
	validationError := func(format string, args ...interface{}) error {
		return fmt.Errorf("invalid server CA certificate: "+format, args...)
	}

	uris, err := uri.GetURINamesFromCertificate(cert)
	if err != nil {
		return validationError("%v", err)
	}

	if len(uris) != 1 {
		return validationError("found %v URI(s); must have exactly one", len(uris))
	}

	keyUsageExtensions := uri.GetKeyUsageExtensionsFromCertificate(cert)

	if len(keyUsageExtensions) == 0 {
		return validationError("key usage extension must be set")
	}

	if !keyUsageExtensions[0].Critical {
		return validationError("key usage extension must be marked critical")
	}

	if idutil.ValidateSpiffeID(uris[0], idutil.AllowTrustDomain(trustDomain)); err != nil {
		return validationError("%v", err)
	}

	if cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && cert.MaxPathLenZero) {
		return validationError("pathLenConstraint must not be set")
	}

	if !cert.IsCA {
		return validationError("must be a CA")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return validationError("KeyUsageCertSign must be set")
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
		return validationError("KeyUsageKeyEncipherment must not be set")
	}

	if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
		return validationError("KeyUsageKeyAgreement must not be set")
	}

	return nil
}
