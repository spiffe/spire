package x509svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
)

const (
	DefaultUpstreamCABackdate = time.Second * 10
	DefaultUpstreamCATTL      = time.Hour
)

type UpstreamCAOptions struct {
	Backdate     time.Duration
	TTL          time.Duration
	SerialNumber SerialNumber
}

type UpstreamCA struct {
	keypair     Keypair
	trustDomain string
	options     UpstreamCAOptions
}

func NewUpstreamCA(keypair Keypair, trustDomain string, options UpstreamCAOptions) *UpstreamCA {
	if options.Backdate <= 0 {
		options.Backdate = DefaultUpstreamCABackdate
	}
	if options.TTL <= 0 {
		options.TTL = DefaultUpstreamCATTL
	}
	if options.SerialNumber == nil {
		options.SerialNumber = NewSerialNumber()
	}

	return &UpstreamCA{
		keypair:     keypair,
		trustDomain: trustDomain,
		options:     options,
	}
}

func (ca *UpstreamCA) SignCSR(ctx context.Context, csrDER []byte) (*x509.Certificate, error) {
	csr, err := ParseAndValidateCSR(csrDER, idutil.AllowTrustDomain(ca.trustDomain))
	if err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyId(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	notBefore := now.Add(-ca.options.Backdate)
	notAfter := now.Add(ca.options.TTL)

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
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA: true,
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
