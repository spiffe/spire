package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/x509util"
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
	SignX509SVID(ctx context.Context, params X509SVIDParams) ([]*x509.Certificate, error)
	SignX509CASVID(ctx context.Context, params X509CASVIDParams) ([]*x509.Certificate, error)
	SignJWTSVID(ctx context.Context, params JWTSVIDParams) (string, error)

	// Sign an SVID used to serve SPIRE server TLS endpoints
	// This is required because in some cases, an UpstreamCA root is used to bootstrap
	// agents while upstream_bundle is false. This allows the trust domain roots to be
	// isolated to those managed by SPIRE, but at the same time allows leveraging a stable
	// upstream root for the sole purpose of bootstrapping agents.
	//
	// This should probably not be supported in the long run because simply omitting higher
	// order CA certificates is 1) not a sufficient isolation mechanism [1] and 2) not supported
	// by most X.509 validators without a special flag set [2].
	//
	// All known instances requiring this use case are isolated to demos and other convenience
	// functions, meaning that the UpstreamCA signer is always the root. To support this specific
	// use case, while also minimizing disruption to the CA implementation and interfaces, this
	// method will always return the CA certificate managed by SPIRE as the 2nd element in the
	// certificate chain. No effort will be made to support this use case when the UpstreamCA
	// signer is not the root.
	//
	// TODO: Change the upstream_ca configurable to default to true. Evaluate whether this use
	// case should be supported in the long term.
	//
	// [1]: https://acmccs.github.io/papers/p1407-acerA.pdf
	// [2]: https://www.openssl.org/docs/man1.1.0/man1/openssl-verify.html
	SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error)
}

// X509SVIDParams are parameters relevant to X509 SVID creation
type X509SVIDParams struct {
	// SPIFFE ID of the SVID
	SpiffeID string

	// Public Key
	PublicKey crypto.PublicKey

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// DNSList is used to add DNS SAN's to the X509 SVID. The first entry
	// is also added as the CN.
	DNSList []string
}

// X509CASVIDParams are parameters relevant to X509 CA SVID creation
type X509CASVIDParams struct {
	// SPIFFE ID of the SVID
	SpiffeID string

	// Public Key
	PublicKey crypto.PublicKey

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration
}

// X509CASVIDParams are parameters relevant to X509 CA SVID creation
type ServerX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey
}

// JWTSVIDParams are parameters relevant to JWT SVID creation
type JWTSVIDParams struct {
	// SPIFFE ID of the SVID
	SpiffeID string

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// Audience is used for audience claims
	Audience []string
}

type X509CA struct {
	// Signer is used to sign child certificates.
	Signer crypto.Signer

	// Certificate is the CA certificate.
	Certificate *x509.Certificate

	// UpstreamChain contains the CA certificate and intermediates necessary to
	// chain back to the upstream trust bundle. It is only set if the CA is
	// signed by an UpstreamCA and the upstream trust bundle *is* the SPIRE
	// trust bundle (see the upstream_bundle configurable).
	UpstreamChain []*x509.Certificate
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
	JWTSVIDTTL  time.Duration
	Clock       clock.Clock
	CASubject   pkix.Name
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
	if config.JWTSVIDTTL <= 0 {
		config.JWTSVIDTTL = DefaultJWTSVIDTTL
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

func (ca *CA) SignX509SVID(ctx context.Context, params X509SVIDParams) ([]*x509.Certificate, error) {
	return ca.signX509SVID(ctx, params, ca.X509CA())
}

func (ca *CA) SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA := ca.X509CA()

	certs, err := ca.signX509SVID(ctx, X509SVIDParams{
		SpiffeID:  idutil.ServerID(ca.c.TrustDomain.Host),
		PublicKey: params.PublicKey,
	}, x509CA)
	if err != nil {
		return nil, err
	}

	// If we don't have an upstream chain, always add our local CA cert to
	// the chain in order to support use cases in which an UpstreamCA is used
	// for bootstrapping only. Don't worry if an UpstreamCA is actually set or
	// not because the cost of transmitting the extra cert is relatively low.
	if len(x509CA.UpstreamChain) == 0 {
		certs = append(certs, x509CA.Certificate)
	}

	return certs, nil
}

func (ca *CA) signX509SVID(ctx context.Context, params X509SVIDParams, x509CA *X509CA) ([]*x509.Certificate, error) {
	if x509CA == nil {
		return nil, errs.New("X509 CA is not available for signing")
	}

	if params.TTL <= 0 {
		params.TTL = ca.c.X509SVIDTTL
	}

	notBefore, notAfter := ca.capLifetime(params.TTL, x509CA.Certificate.NotAfter)
	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, err
	}

	template, err := CreateX509SVIDTemplate(params.SpiffeID, params.PublicKey, ca.c.TrustDomain.Host, notBefore, notAfter, serialNumber)
	if err != nil {
		return nil, err
	}
	// Explicitly set the AKI on the signed certificate, otherwise it won't be
	// added if the subject and issuer match name match (however unlikely).
	template.AuthorityKeyId = x509CA.Certificate.SubjectKeyId

	// for non-CA certificates, add DNS names to certificate. the first DNS
	// name is also added as the common name.
	if len(params.DNSList) > 0 {
		template.Subject.CommonName = params.DNSList[0]
		template.DNSNames = params.DNSList
	}

	cert, err := createCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, errs.New("unable to create X509 SVID: %v", err)
	}

	spiffeID := cert.URIs[0].String()

	ca.c.Log.WithFields(logrus.Fields{
		telemetry.SPIFFEID:   spiffeID,
		telemetry.Expiration: cert.NotAfter.Format(time.RFC3339),
	}).Debug("Signed X509 SVID")

	telemetry_server.IncrServerCASignX509Counter(ca.c.Metrics, spiffeID)

	return makeSVIDCertChain(x509CA, cert), nil
}

func (ca *CA) SignX509CASVID(ctx context.Context, params X509CASVIDParams) ([]*x509.Certificate, error) {
	x509CA := ca.X509CA()
	if x509CA == nil {
		return nil, errs.New("X509 CA is not available for signing")
	}

	if params.TTL <= 0 {
		params.TTL = ca.c.X509SVIDTTL
	}

	notBefore, notAfter := ca.capLifetime(params.TTL, x509CA.Certificate.NotAfter)
	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, err
	}

	// Don't allow the downstream server to control the subject of the CA
	// certificate. Additionally, set the OU to a 1-based downstream "level"
	// for soft debugging support.
	subject := x509CA.Certificate.Subject
	subject.OrganizationalUnit = []string{fmt.Sprintf("DOWNSTREAM-%d", 1+len(x509CA.UpstreamChain))}

	template, err := CreateServerCATemplate(params.SpiffeID, params.PublicKey, ca.c.TrustDomain.Host, notBefore, notAfter, serialNumber, subject)
	if err != nil {
		return nil, err
	}
	// Explicitly set the AKI on the signed certificate, otherwise it won't be
	// added if the subject and issuer match name matches (unlikely due to the
	// OU override below, but just to be safe).
	template.AuthorityKeyId = x509CA.Certificate.SubjectKeyId

	cert, err := createCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, errs.New("unable to create X509 CA SVID: %v", err)
	}

	spiffeID := cert.URIs[0].String()

	ca.c.Log.WithFields(logrus.Fields{
		telemetry.SPIFFEID:   spiffeID,
		telemetry.Expiration: cert.NotAfter.Format(time.RFC3339),
	}).Debug("Signed X509 CA SVID")

	telemetry_server.IncrServerCASignX509CACounter(ca.c.Metrics, spiffeID)

	return makeSVIDCertChain(x509CA, cert), nil
}

func (ca *CA) SignJWTSVID(ctx context.Context, params JWTSVIDParams) (string, error) {
	jwtKey := ca.JWTKey()
	if jwtKey == nil {
		return "", errs.New("JWT key is not available for signing")
	}

	if err := idutil.ValidateSpiffeID(params.SpiffeID, idutil.AllowTrustDomainWorkload(ca.c.TrustDomain.Host)); err != nil {
		return "", err
	}

	ttl := params.TTL
	if ttl <= 0 {
		ttl = ca.c.JWTSVIDTTL
	}
	_, expiresAt := ca.capLifetime(ttl, jwtKey.NotAfter)

	token, err := ca.jwtSigner.SignToken(params.SpiffeID, params.Audience, expiresAt, jwtKey.Signer, jwtKey.Kid)
	if err != nil {
		return "", errs.New("unable to sign JWT SVID: %v", err)
	}

	telemetry_server.IncrServerCASignJWTSVIDCounter(ca.c.Metrics, params.SpiffeID)

	return token, nil
}

func (ca *CA) capLifetime(ttl time.Duration, expirationCap time.Time) (notBefore, notAfter time.Time) {
	now := ca.c.Clock.Now()
	notBefore = now.Add(-backdate)
	notAfter = now.Add(ttl)
	if notAfter.After(expirationCap) {
		notAfter = expirationCap
	}
	return notBefore, notAfter
}

func makeSVIDCertChain(x509CA *X509CA, cert *x509.Certificate) []*x509.Certificate {
	return append([]*x509.Certificate{cert}, x509CA.UpstreamChain...)
}

func createCertificate(template, parent *x509.Certificate, pub, priv interface{}) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, errs.New("unable to create X509 SVID: %v", err)
	}

	return x509.ParseCertificate(certDER)
}
