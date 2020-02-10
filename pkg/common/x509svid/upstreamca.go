package x509svid

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
)

const (
	DefaultUpstreamCABackdate = time.Second * 10
	DefaultUpstreamCATTL      = time.Hour
)

type UpstreamCAOptions struct {
	Backdate time.Duration
	TTL      time.Duration
	Clock    clock.Clock
}

type UpstreamCA struct {
	keypair     x509util.Keypair
	trustDomain string
	options     UpstreamCAOptions
}

func NewUpstreamCA(keypair x509util.Keypair, trustDomain string, options UpstreamCAOptions) *UpstreamCA {
	if options.Backdate <= 0 {
		options.Backdate = DefaultUpstreamCABackdate
	}
	if options.Clock == nil {
		options.Clock = clock.New()
	}

	return &UpstreamCA{
		keypair:     keypair,
		trustDomain: trustDomain,
		options:     options,
	}
}

func (ca *UpstreamCA) SignCSR(ctx context.Context, csrDER []byte, preferredTTL time.Duration) (*x509.Certificate, error) {
	csr, err := ParseAndValidateCSR(csrDER, idutil.AllowTrustDomain(ca.trustDomain))
	if err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	// Prefer the CA TTL setting, if configured. Then fall back to the
	// "preferred TTL in the request. Finally, if neither is set, use the
	// default.
	caTTL := DefaultUpstreamCATTL
	switch {
	case ca.options.TTL > 0:
		caTTL = ca.options.TTL
	case preferredTTL > 0:
		caTTL = preferredTTL
	}

	now := ca.options.Clock.Now()
	notBefore := now.Add(-ca.options.Backdate)
	notAfter := now.Add(caTTL)

	caCert, err := ca.keypair.GetCertificate(ctx)
	if err != nil {
		return nil, err
	}
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}

	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		URIs:         csr.URIs,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
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
