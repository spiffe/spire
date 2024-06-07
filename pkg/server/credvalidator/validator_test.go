package credvalidator_test

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var (
	now        = time.Now().Add(time.Hour).Truncate(time.Minute)
	td         = spiffeid.RequireTrustDomainFromString("domain.test")
	caID       = td.ID()
	serverID   = spiffeid.RequireFromPath(td, "/spire/server")
	workloadID = spiffeid.RequireFromPath(td, "/workload")
	jwtKey     = testkey.MustEC256()
)

func TestValidateX509CA(t *testing.T) {
	for _, tc := range []struct {
		desc      string
		setup     func(ca *x509.Certificate)
		expectErr string
	}{
		{
			desc:  "bare minimum",
			setup: func(ca *x509.Certificate) {},
		},
		{
			desc: "basic constraints not valid",
			setup: func(ca *x509.Certificate) {
				ca.BasicConstraintsValid = false
			},
			expectErr: "invalid X509 CA: basic constraints are not valid",
		},
		{
			desc: "cA constraint is not set",
			setup: func(ca *x509.Certificate) {
				ca.IsCA = false
			},
			expectErr: "invalid X509 CA: cA constraint is not set",
		},
		{
			desc: "certSign key usage is not set",
			setup: func(ca *x509.Certificate) {
				ca.KeyUsage = 0
			},
			expectErr: "invalid X509 CA: keyCertSign key usage must be set",
		},
		{
			desc: "cRLSign key usage",
			setup: func(ca *x509.Certificate) {
				ca.KeyUsage |= x509.KeyUsageCRLSign
			},
		},
		{
			desc: "digitalSignature key usage",
			setup: func(ca *x509.Certificate) {
				ca.KeyUsage |= x509.KeyUsageDigitalSignature
			},
		},
		{
			desc: "key usage other than certSign, cRLSign, and digitalSignature",
			setup: func(ca *x509.Certificate) {
				ca.KeyUsage |= x509.KeyUsageKeyAgreement
			},
			expectErr: "invalid X509 CA: only keyCertSign, cRLSign, or digitalSignature key usage can be set",
		},
		{
			desc: "no URI SAN",
			setup: func(ca *x509.Certificate) {
				ca.URIs = nil
			},
		},
		{
			desc: "more than one URI SAN",
			setup: func(ca *x509.Certificate) {
				ca.URIs = append(ca.URIs, serverID.URL())
			},
			expectErr: `invalid X509 CA: expected URI SAN "spiffe://domain.test" but got ["spiffe://domain.test" "spiffe://domain.test/spire/server"]`,
		},
		{
			desc: "unexpected URI SAN",
			setup: func(ca *x509.Certificate) {
				ca.URIs = []*url.URL{serverID.URL()}
			},
			expectErr: `invalid X509 CA: expected URI SAN "spiffe://domain.test" but got "spiffe://domain.test/spire/server"`,
		},
		{
			desc: "not yet valid",
			setup: func(ca *x509.Certificate) {
				ca.NotBefore = now.Add(time.Second)
			},
			expectErr: fmt.Sprintf(`invalid X509 CA: not yet valid until %s`, now.Add(time.Second).Format(time.RFC3339)),
		},
		{
			desc: "already expired",
			setup: func(ca *x509.Certificate) {
				ca.NotAfter = now.Add(-time.Second)
			},
			expectErr: fmt.Sprintf(`invalid X509 CA: already expired as of %s`, now.Add(-time.Second).Format(time.RFC3339)),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			validator := newValidator(t)
			ca := &x509.Certificate{
				BasicConstraintsValid: true,
				IsCA:                  true,
				NotBefore:             now.Add(-time.Minute),
				NotAfter:              now.Add(time.Minute),
				KeyUsage:              x509.KeyUsageCertSign,
				URIs:                  []*url.URL{caID.URL()},
			}
			require.NotNil(t, tc.setup, "test must provide the setup callback")
			if tc.setup != nil {
				tc.setup(ca)
			}
			err := validator.ValidateX509CA(ca)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateX509SVID(t *testing.T) {
	for _, tc := range []struct {
		desc      string
		setup     func(svid *x509.Certificate)
		expectErr string
	}{
		{
			desc:  "bare minimum",
			setup: func(svid *x509.Certificate) {},
		},
		{
			desc: "basic constraints not valid",
			setup: func(svid *x509.Certificate) {
				svid.BasicConstraintsValid = false
			},
			expectErr: "invalid X509-SVID: basic constraints are not valid",
		},
		{
			desc: "cA constraint is set",
			setup: func(svid *x509.Certificate) {
				svid.IsCA = true
			},
			expectErr: "invalid X509-SVID: cA constraint must not be set",
		},
		{
			desc: "digitalSignature key usage is not set",
			setup: func(svid *x509.Certificate) {
				svid.KeyUsage = 0
			},
			expectErr: "invalid X509-SVID: digitalSignature key usage must be set",
		},
		{
			desc: "keyEncipherment key usage",
			setup: func(svid *x509.Certificate) {
				svid.KeyUsage |= x509.KeyUsageKeyEncipherment
			},
		},
		{
			desc: "keyAgreement key usage",
			setup: func(svid *x509.Certificate) {
				svid.KeyUsage |= x509.KeyUsageKeyAgreement
			},
		},
		{
			desc: "key usage other than digitalSignature, keyEncipherment, and keyAgreement",
			setup: func(svid *x509.Certificate) {
				svid.KeyUsage |= x509.KeyUsageCRLSign
			},
			expectErr: "invalid X509-SVID: only digitalSignature, keyEncipherment, and keyAgreement key usage can be set",
		},
		{
			desc: "no extended key usage",
			setup: func(svid *x509.Certificate) {
				svid.ExtKeyUsage = nil
			},
		},
		{
			desc: "missing serverAuth",
			setup: func(svid *x509.Certificate) {
				svid.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectErr: "invalid X509-SVID: missing serverAuth extended key usage",
		},
		{
			desc: "missing clientAuth",
			setup: func(svid *x509.Certificate) {
				svid.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectErr: "invalid X509-SVID: missing clientAuth extended key usage",
		},
		{
			desc: "missing both serverAuth clientAuth",
			setup: func(svid *x509.Certificate) {
				svid.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
			},
			expectErr: "invalid X509-SVID: missing both serverAuth and clientAuth extended key usage",
		},
		{
			desc: "no URI SAN",
			setup: func(svid *x509.Certificate) {
				svid.URIs = nil
			},
			expectErr: "invalid X509-SVID: missing URI SAN",
		},
		{
			desc: "more than one URI SAN",
			setup: func(svid *x509.Certificate) {
				svid.URIs = append(svid.URIs, caID.URL())
			},
			expectErr: `invalid X509-SVID: expected URI SAN "spiffe://domain.test/spire/server" but got ["spiffe://domain.test/spire/server" "spiffe://domain.test"]`,
		},
		{
			desc: "unexpected URI SAN",
			setup: func(svid *x509.Certificate) {
				svid.URIs = []*url.URL{caID.URL()}
			},
			expectErr: `invalid X509-SVID: expected URI SAN "spiffe://domain.test/spire/server" but got "spiffe://domain.test"`,
		},
		{
			desc: "not yet valid",
			setup: func(svid *x509.Certificate) {
				svid.NotBefore = now.Add(time.Second)
			},
			expectErr: fmt.Sprintf(`invalid X509-SVID: not yet valid until %s`, now.Add(time.Second).Format(time.RFC3339)),
		},
		{
			desc: "already expired",
			setup: func(svid *x509.Certificate) {
				svid.NotAfter = now.Add(-time.Second)
			},
			expectErr: fmt.Sprintf(`invalid X509-SVID: already expired as of %s`, now.Add(-time.Second).Format(time.RFC3339)),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			validator := newValidator(t)
			svid := &x509.Certificate{
				BasicConstraintsValid: true,
				IsCA:                  false,
				NotBefore:             now.Add(-time.Minute),
				NotAfter:              now.Add(time.Minute),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				URIs:                  []*url.URL{serverID.URL()},
			}
			require.NotNil(t, tc.setup, "test must provide the setup callback")
			if tc.setup != nil {
				tc.setup(svid)
			}
			err := validator.ValidateX509SVID(svid, serverID)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateWorkloadJWTSVID(t *testing.T) {
	for _, tc := range []struct {
		desc          string
		setup         func(claims *jwt.Claims)
		makeJWT       func(t *testing.T, claims any) string
		tokenOverride string
		expectErr     string
	}{
		{
			desc:  "bare minimum",
			setup: func(claims *jwt.Claims) {},
		},
		{
			desc:  "malformed JWT",
			setup: func(claims *jwt.Claims) {},
			makeJWT: func(t *testing.T, claims any) string {
				return "not-a-jwt"
			},
			expectErr: "failed to parse JWT-SVID for validation: go-jose/go-jose: compact JWS format must have three parts",
		},
		{
			desc:  "malformed claims",
			setup: func(claims *jwt.Claims) {},
			makeJWT: func(t *testing.T, claims any) string {
				return makeJWT(t, map[string]any{
					"aud": 1,
				})
			},
			expectErr: "failed to extract JWT-SVID claims for validation: go-jose/go-jose/jwt: expected string or array value to unmarshal to Audience",
		},
		{
			desc: "unexpected subject",
			setup: func(claims *jwt.Claims) {
				claims.Subject = "foo"
			},
			expectErr: `invalid JWT-SVID "sub" claim: expected "spiffe://domain.test/workload" but got "foo"`,
		},
		{
			desc: "missing expiry",
			setup: func(claims *jwt.Claims) {
				claims.Expiry = nil
			},
			expectErr: `invalid JWT-SVID "exp" claim: required but missing`,
		},
		{
			desc: "already expired",
			setup: func(claims *jwt.Claims) {
				claims.Expiry = jwt.NewNumericDate(now.Add(-time.Second))
			},
			expectErr: fmt.Sprintf(`invalid JWT-SVID "exp" claim: already expired as of %s`, now.Add(-time.Second).Format(time.RFC3339)),
		},
		{
			desc: "not yet valid",
			setup: func(claims *jwt.Claims) {
				claims.NotBefore = jwt.NewNumericDate(now.Add(time.Second))
			},
			expectErr: fmt.Sprintf(`invalid JWT-SVID "nbf" claim: not yet valid until %s`, now.Add(time.Second).Format(time.RFC3339)),
		},
		{
			desc: "missing audience",
			setup: func(claims *jwt.Claims) {
				claims.Audience = nil
			},
			expectErr: `invalid JWT-SVID "aud" claim: required but missing`,
		},
		{
			desc: "audience has empty value",
			setup: func(claims *jwt.Claims) {
				claims.Audience = []string{""}
			},
			expectErr: `invalid JWT-SVID "aud" claim: contains empty value`,
		},
		{
			desc: "more than one audience",
			setup: func(claims *jwt.Claims) {
				claims.Audience = append(claims.Audience, "AUDIENCE2")
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			validator := newValidator(t)
			claims := &jwt.Claims{
				Subject:  workloadID.String(),
				Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
				Audience: []string{"AUDIENCE1"},
			}
			require.NotNil(t, tc.setup, "test must provide the setup callback")
			if tc.setup != nil {
				tc.setup(claims)
			}

			makeJWTFunc := makeJWT
			if tc.makeJWT != nil {
				makeJWTFunc = tc.makeJWT
			}

			token := makeJWTFunc(t, claims)

			err := validator.ValidateWorkloadJWTSVID(token, workloadID)
			if tc.expectErr != "" {
				require.EqualError(t, err, tc.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func newValidator(t *testing.T) *credvalidator.Validator {
	validator, err := credvalidator.New(credvalidator.Config{
		TrustDomain: td,
		Clock:       clock.NewMockAt(t, now),
	})
	require.NoError(t, err)
	return validator
}

func makeJWT(t *testing.T, claims any) string {
	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: jwtKey}
	signer, err := jose.NewSigner(signingKey, nil)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}
