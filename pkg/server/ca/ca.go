package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/zeebo/errs"
)

const (
	// DefaultX509SVIDTTL is the TTL given to X509 SVIDs if not overridden by
	// the server config.
	DefaultX509SVIDTTL = time.Hour

	// DefaultJWTSVIDTTL is the TTL given to JWT SVIDs if a different TTL is
	// not provided in the signing request.
	DefaultJWTSVIDTTL = time.Minute * 5
)

// ServerCA is an interface for Server CAs
type ServerCA interface {
	SignX509SVID(ctx context.Context, csrDER []byte, params X509Params) ([]*x509.Certificate, error)
	SignX509CASVID(ctx context.Context, csrDER []byte, params X509Params) ([]*x509.Certificate, error)
	SignJWTSVID(ctx context.Context, jsr *node.JSR) (string, error)
}

// X509Params are parameters relevant to X509 SVID creation
type X509Params struct {
	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// DNSList is used to add DNS SAN's to the X509 SVID. The first entry
	// is also added as the CN. DNSList is ignored when signing CA X509 SVIDs.
	DNSList []string
}

type X509CA struct {
	// The signer used to create child certificates
	Signer crypto.Signer

	// Chain contains the certificate chain of the CA. It will be a single
	// certificate when self signed or when it has been signed by an Upstream
	// CA but the upstream trust bundle was not included in the SPIRE trust
	// bundle (see upstream_bundle configurable). Otherwise it will contain
	// the CA certificate and any intermediates necessary to chain back to the
	// upstream trust bundle.
	Chain []*x509.Certificate

	// IsIntermediate is true if the CA certificate is considered an
	// intermediate to another certificate in the trust bundle. This is the
	// case when it has been signed by an Upstream CA and the upstream trust
	// bundle was included in the SPIRE trust bundle (see the upstream_bundle
	// configurable).
	IsIntermediate bool
}

type JWTKey struct {
	// The signer used to sign keys
	Signer crypto.Signer

	// Kid is the JWT key ID (i.e. "kid" claim)
	Kid string

	// NotAfter is the expiration time of the JWT key.
	NotAfter time.Time
}

type CAConfig struct {
	Log         logrus.FieldLogger
	Metrics     telemetry.Metrics
	TrustDomain url.URL
	X509SVIDTTL time.Duration
	Clock       clock.Clock
}

type CA struct {
	c      CAConfig
	x509sn int64

	mu     sync.RWMutex
	x509CA *X509CA
	jwtKey *JWTKey

	jwtSigner *jwtsvid.Signer
}

func NewCA(config CAConfig) *CA {
	if config.X509SVIDTTL <= 0 {
		config.X509SVIDTTL = DefaultX509SVIDTTL
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	return &CA{
		c: config,
		jwtSigner: jwtsvid.NewSigner(jwtsvid.SignerConfig{
			Clock: config.Clock,
		}),
	}
}

func (ca *CA) X509CA() *X509CA {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.x509CA
}

func (ca *CA) SetX509CA(x509CA *X509CA) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.x509CA = x509CA
}

func (ca *CA) JWTKey() *JWTKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.jwtKey
}

func (ca *CA) SetJWTKey(jwtKey *JWTKey) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.jwtKey = jwtKey
}

func (ca *CA) SignX509SVID(ctx context.Context, csrDER []byte, params X509Params) ([]*x509.Certificate, error) {
	return ca.signX509SVID(ctx, csrDER, params, false)
}

func (ca *CA) SignX509CASVID(ctx context.Context, csrDER []byte, params X509Params) ([]*x509.Certificate, error) {
	return ca.signX509SVID(ctx, csrDER, params, true)
}

func (ca *CA) SignJWTSVID(ctx context.Context, jsr *node.JSR) (string, error) {
	jwtKey := ca.JWTKey()
	if jwtKey == nil {
		return "", errs.New("JWT key is not available for signing")
	}

	if err := idutil.ValidateSpiffeID(jsr.SpiffeId, idutil.AllowTrustDomainWorkload(ca.c.TrustDomain.Host)); err != nil {
		return "", err
	}

	ttl := time.Duration(jsr.Ttl) * time.Second
	if ttl <= 0 {
		ttl = DefaultJWTSVIDTTL
	}
	_, expiresAt := ca.calculateLifetime(ttl, jwtKey.NotAfter)

	token, err := ca.jwtSigner.SignToken(jsr.SpiffeId, jsr.Audience, expiresAt, jwtKey.Signer, jwtKey.Kid)
	if err != nil {
		return "", errs.New("unable to sign JWT SVID: %v", err)
	}

	labels := []telemetry.Label{
		{
			Name:  "spiffe_id",
			Value: jsr.SpiffeId,
		},
	}
	for _, audience := range jsr.Audience {
		labels = append(labels, telemetry.Label{
			Name:  "audience",
			Value: audience,
		})
	}
	ca.c.Metrics.IncrCounterWithLabels([]string{"server_ca", "sign", "jwt_svid"}, 1, labels)

	return token, nil
}

func (ca *CA) signX509SVID(ctx context.Context, csrDER []byte, params X509Params, isCA bool) ([]*x509.Certificate, error) {
	x509CA := ca.X509CA()
	if x509CA == nil {
		return nil, errs.New("X509 CA is not available for signing")
	}

	if params.TTL <= 0 {
		params.TTL = ca.c.X509SVIDTTL
	}

	notBefore, notAfter := ca.calculateLifetime(params.TTL, x509CA.Chain[0].NotAfter)
	serialNumber := ca.nextSerialNumber()

	template, err := CreateX509SVIDTemplate(csrDER, ca.c.TrustDomain.Host, notBefore, notAfter, serialNumber)
	if err != nil {
		return nil, err
	}

	// for non-CA certificates, add DNS names to certificate. the first DNS
	// name is also added as the common name.
	if !isCA && len(params.DNSList) > 0 {
		template.Subject.CommonName = params.DNSList[0]
		template.DNSNames = params.DNSList
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, x509CA.Chain[0], template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, errs.New("unable to create X509 SVID: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	spiffeID := cert.URIs[0].String()

	ca.c.Log.WithFields(logrus.Fields{
		"is_ca":      isCA,
		"spiffe_id":  spiffeID,
		"expires_at": cert.NotAfter.Format(time.RFC3339),
	}).Debug("Signed X509 SVID")

	ca.c.Metrics.IncrCounterWithLabels([]string{"ca", "sign", "x509_svid"}, 1, []telemetry.Label{
		{
			Name:  "spiffe_id",
			Value: spiffeID,
		},
		{
			Name:  "is_ca",
			Value: fmt.Sprint(isCA),
		},
	})

	return makeSVIDCertChain(x509CA, cert), nil
}

func (ca *CA) nextSerialNumber() *big.Int {
	return big.NewInt(atomic.AddInt64(&ca.x509sn, 1))
}

func (ca *CA) calculateLifetime(ttl time.Duration, expirationCap time.Time) (notBefore, notAfter time.Time) {
	now := ca.c.Clock.Now()
	notBefore = now.Add(-backdate)
	notAfter = now.Add(ttl)
	if notAfter.After(expirationCap) {
		notAfter = expirationCap
	}
	return notBefore, notAfter
}

func makeSVIDCertChain(x509CA *X509CA, cert *x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{cert}
	if x509CA.IsIntermediate {
		chain = append(chain, x509CA.Chain...)
	}
	return chain
}
