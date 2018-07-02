package jwtsvid

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	certificateThumbprintHeader = "x5t#S256"
)

func SignSimpleToken(spiffeID string, audience []string, expires time.Time, privateKey *ecdsa.PrivateKey, cert *x509.Certificate) (string, error) {
	// this might be overkill but better safe than sorry.
	if publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !ecdsaKeyMatches(privateKey, publicKey) {
		return "", errors.New("certificate does not match private key")
	}
	if err := idutil.ValidateSpiffeID(spiffeID, idutil.AllowAnyTrustDomainWorkload()); err != nil {
		return "", err
	}

	// cap expiration to the signing certificate expiration, if necessary.
	if expires.IsZero() {
		return "", errors.New("expiration is required")
	}
	if !cert.NotAfter.IsZero() && expires.After(cert.NotAfter) {
		expires = cert.NotAfter
	}

	if len(audience) == 0 {
		return "", errors.New("audience is required")
	}

	claims := jwt.MapClaims{
		"sub": spiffeID,
		"exp": expires.Unix(),
		"aud": audienceClaim(audience),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header[certificateThumbprintHeader] = certificateThumbprint(cert)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

type SimpleTrustBundle interface {
	FindCertificate(ctx context.Context, thumbprint string) (*x509.Certificate, error)
}

type simpleTrustBundle struct {
	lookup map[string]*x509.Certificate
}

func NewSimpleTrustBundle(certs []*x509.Certificate) SimpleTrustBundle {
	t := &simpleTrustBundle{
		lookup: make(map[string]*x509.Certificate),
	}
	for _, cert := range certs {
		t.lookup[certificateThumbprint(cert)] = cert
	}
	return t
}

func (t *simpleTrustBundle) FindCertificate(ctx context.Context, thumbprint string) (*x509.Certificate, error) {
	cert := t.lookup[thumbprint]
	if cert == nil {
		return nil, errors.New("signing certificate not found in trust bundle")
	}
	return cert, nil
}

func ValidateSimpleToken(ctx context.Context, token string, trustBundle SimpleTrustBundle, audience string) (jwt.MapClaims, error) {
	claims := make(jwt.MapClaims)
	if _, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, fmt.Errorf("unexpected token signature algorithm: %s", t.Method.Alg())
		}
		thumbprint, _ := t.Header[certificateThumbprintHeader].(string)
		if thumbprint == "" {
			return nil, errors.New("token missing certificate thumbprint")
		}
		cert, err := trustBundle.FindCertificate(ctx, thumbprint)
		if err != nil {
			return nil, err
		}
		if err := ValidateSigningCertificate(cert); err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	}); err != nil {
		return nil, err
	}

	switch audienceClaim := claims["aud"].(type) {
	case []interface{}:
		found := false
		for _, audValue := range audienceClaim {
			if aud, ok := audValue.(string); ok && aud == audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("expected audience %q (audience=%q)", audience, audienceClaim)
		}
	case string:
		if audienceClaim != audience {
			return nil, fmt.Errorf("expected audience %q (audience=%q)", audience, audienceClaim)
		}
	default:
		return nil, errors.New("missing audience claim")
	}
	return claims, nil
}

func certificateThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.URLEncoding.EncodeToString(hash[:])
}
