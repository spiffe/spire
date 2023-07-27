package credvalidator

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Config struct {
	Clock       clock.Clock
	TrustDomain spiffeid.TrustDomain
}

type Validator struct {
	clock    clock.Clock
	x509CAID spiffeid.ID
	serverID spiffeid.ID
}

func New(config Config) (*Validator, error) {
	if config.TrustDomain.IsZero() {
		return nil, errors.New("trust domain must be set")
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	serverID, err := idutil.ServerID(config.TrustDomain)
	if err != nil {
		// This check is purely defensive; idutil.ServerID should not fail since the trust domain is valid.
		return nil, err
	}
	return &Validator{
		clock:    config.Clock,
		x509CAID: config.TrustDomain.ID(),
		serverID: serverID,
	}, nil
}

func (v *Validator) ValidateX509CA(ca *x509.Certificate) error {
	if !ca.BasicConstraintsValid {
		return errors.New("invalid X509 CA: basic constraints are not valid")
	}
	if !ca.IsCA {
		return errors.New("invalid X509 CA: cA constraint is not set")
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("invalid X509 CA: keyCertSign key usage must be set")
	}
	if ca.KeyUsage&^(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature) > 0 {
		return errors.New("invalid X509 CA: only keyCertSign, cRLSign, or digitalSignature key usage can be set")
	}
	if err := checkURISAN(ca, true, v.x509CAID); err != nil {
		return fmt.Errorf("invalid X509 CA: %w", err)
	}
	if err := checkX509CertificateExpiration(ca, v.clock.Now()); err != nil {
		return fmt.Errorf("invalid X509 CA: %w", err)
	}
	return nil
}

func (v *Validator) ValidateServerX509SVID(svid *x509.Certificate) error {
	return v.ValidateX509SVID(svid, v.serverID)
}

func (v *Validator) ValidateX509SVID(svid *x509.Certificate, id spiffeid.ID) error {
	if !svid.BasicConstraintsValid {
		return errors.New("invalid X509-SVID: basic constraints are not valid")
	}
	if svid.IsCA {
		return errors.New("invalid X509-SVID: cA constraint must not be set")
	}
	if svid.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("invalid X509-SVID: digitalSignature key usage must be set")
	}
	if svid.KeyUsage&^(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) > 0 {
		return errors.New("invalid X509-SVID: only digitalSignature, keyEncipherment, and keyAgreement key usage can be set")
	}

	if len(svid.ExtKeyUsage) > 0 {
		hasServerAuth := hasExtKeyUsage(svid.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		hasClientAuth := hasExtKeyUsage(svid.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		switch {
		case !hasServerAuth && hasClientAuth:
			return errors.New("invalid X509-SVID: missing serverAuth extended key usage")
		case hasServerAuth && !hasClientAuth:
			return errors.New("invalid X509-SVID: missing clientAuth extended key usage")
		case !hasServerAuth && !hasClientAuth:
			return errors.New("invalid X509-SVID: missing both serverAuth and clientAuth extended key usage")
		}
	}

	if err := checkURISAN(svid, false, id); err != nil {
		return fmt.Errorf("invalid X509-SVID: %w", err)
	}
	if err := checkX509CertificateExpiration(svid, v.clock.Now()); err != nil {
		return fmt.Errorf("invalid X509-SVID: %w", err)
	}
	return nil
}

func (v *Validator) ValidateWorkloadJWTSVID(rawToken string, id spiffeid.ID) error {
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return fmt.Errorf("failed to parse JWT-SVID for validation: %w", err)
	}

	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("failed to extract JWT-SVID claims for validation: %w", err)
	}

	now := v.clock.Now()
	switch {
	case claims.Subject != id.String():
		return fmt.Errorf(`invalid JWT-SVID "sub" claim: expected %q but got %q`, id, claims.Subject)
	case claims.Expiry == nil:
		return errors.New(`invalid JWT-SVID "exp" claim: required but missing`)
	case !claims.Expiry.Time().After(now):
		return fmt.Errorf(`invalid JWT-SVID "exp" claim: already expired as of %s`, claims.Expiry.Time().Format(time.RFC3339))
	case claims.NotBefore != nil && claims.NotBefore.Time().After(now):
		return fmt.Errorf(`invalid JWT-SVID "nbf" claim: not yet valid until %s`, claims.NotBefore.Time().Format(time.RFC3339))
	case len(claims.Audience) == 0:
		return errors.New(`invalid JWT-SVID "aud" claim: required but missing`)
	case hasEmptyAudienceValue(claims.Audience):
		return errors.New(`invalid JWT-SVID "aud" claim: contains empty value`)
	}
	return nil
}

func checkURISAN(cert *x509.Certificate, isCA bool, id spiffeid.ID) error {
	if len(cert.URIs) == 0 {
		if isCA {
			// A signing certificate should itself be an SVID, but it's not
			// mandatory.
			return nil
		}
		return errors.New("missing URI SAN")
	}

	// There is at least one URI.
	// These validations apply for both CA and non CA certificates.
	if len(cert.URIs) > 1 {
		return fmt.Errorf("expected URI SAN %q but got %q", id, cert.URIs)
	}
	if cert.URIs[0].String() != id.String() {
		return fmt.Errorf("expected URI SAN %q but got %q", id, cert.URIs[0])
	}
	return nil
}

func checkX509CertificateExpiration(cert *x509.Certificate, now time.Time) error {
	if !cert.NotBefore.IsZero() && now.Before(cert.NotBefore) {
		return fmt.Errorf("not yet valid until %s", cert.NotBefore.Format(time.RFC3339))
	}
	if !cert.NotAfter.IsZero() && now.After(cert.NotAfter) {
		return fmt.Errorf("already expired as of %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func hasExtKeyUsage(extKeyUsage []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, candidate := range extKeyUsage {
		if candidate == want {
			return true
		}
	}
	return false
}

func hasEmptyAudienceValue(audience jwt.Audience) bool {
	// shift audience
	for _, value := range audience {
		if value == "" {
			return true
		}
	}
	return false
}
