package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	backdate = 10 * time.Second
)

// ServerCA is an interface for Server CAs
type ServerCA interface {
	SignDownstreamX509CA(ctx context.Context, params DownstreamX509CAParams) ([]*x509.Certificate, error)
	SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error)
	SignAgentX509SVID(ctx context.Context, params AgentX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error)
}

// DownstreamX509CAParams are parameters relevant to downstream X.509 CA creation
type DownstreamX509CAParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration
}

// ServerX509SVIDParams are parameters relevant to server X509-SVID creation
type ServerX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey
}

// AgentX509SVIDParams are parameters relevant to agent X509-SVID creation
type AgentX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the agent
	SPIFFEID spiffeid.ID
}

// WorkloadX509SVIDParams are parameters relevant to workload X509-SVID creation
type WorkloadX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// DNSNames is used to add DNS SAN's to the X509 SVID. The first entry
	// is also added as the CN.
	DNSNames []string

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// Subject of the SVID. Default subject is used if it is empty.
	Subject pkix.Name
}

// WorkloadJWTSVIDParams are parameters relevant to workload JWT-SVID creation
type WorkloadJWTSVIDParams struct {
	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the token will be capped to that of the signing key.
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
	// signed by an UpstreamCA.
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

type Config struct {
	Log           logrus.FieldLogger
	Clock         clock.Clock
	Metrics       telemetry.Metrics
	TrustDomain   spiffeid.TrustDomain
	CredBuilder   *credtemplate.Builder
	CredValidator *credvalidator.Validator
	HealthChecker health.Checker
}

type CA struct {
	c Config

	mu          sync.RWMutex
	x509CA      *X509CA
	x509CAChain []*x509.Certificate
	jwtKey      *JWTKey
}

func NewCA(config Config) *CA {
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	ca := &CA{
		c: config,
	}

	_ = config.HealthChecker.AddCheck("server.ca", &caHealth{
		ca: ca,
		td: config.TrustDomain,
	})

	return ca
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
	switch {
	case x509CA == nil:
		ca.x509CAChain = nil
	case len(x509CA.UpstreamChain) > 0:
		ca.x509CAChain = x509CA.UpstreamChain
	default:
		ca.x509CAChain = []*x509.Certificate{x509CA.Certificate}
	}
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

func (ca *CA) SignDownstreamX509CA(ctx context.Context, params DownstreamX509CAParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildDownstreamX509CATemplate(ctx, credtemplate.DownstreamX509CAParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		TTL:         params.TTL,
	})
	if err != nil {
		return nil, err
	}

	downstreamCA, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("unable to create downstream X509 CA: %w", err)
	}

	if err := ca.c.CredValidator.ValidateX509CA(downstreamCA); err != nil {
		return nil, fmt.Errorf("invalid downstream X509 CA: %w", err)
	}

	telemetry_server.IncrServerCASignX509CACounter(ca.c.Metrics)

	return makeCertChain(x509CA, downstreamCA), nil
}

func (ca *CA) SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildServerX509SVIDTemplate(ctx, credtemplate.ServerX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateServerX509SVID(svidChain[0]); err != nil {
		return nil, fmt.Errorf("invalid server X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignAgentX509SVID(ctx context.Context, params AgentX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildAgentX509SVIDTemplate(ctx, credtemplate.AgentX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		SPIFFEID:    params.SPIFFEID,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateX509SVID(svidChain[0], params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid agent X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildWorkloadX509SVIDTemplate(ctx, credtemplate.WorkloadX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		SPIFFEID:    params.SPIFFEID,
		DNSNames:    params.DNSNames,
		TTL:         params.TTL,
		Subject:     params.Subject,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(x509CA, template)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateX509SVID(svidChain[0], params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid workload X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error) {
	jwtKey := ca.JWTKey()
	if jwtKey == nil {
		return "", errors.New("JWT key is not available for signing")
	}

	claims, err := ca.c.CredBuilder.BuildWorkloadJWTSVIDClaims(ctx, credtemplate.WorkloadJWTSVIDParams{
		SPIFFEID:      params.SPIFFEID,
		Audience:      params.Audience,
		TTL:           params.TTL,
		ExpirationCap: jwtKey.NotAfter,
	})
	if err != nil {
		return "", err
	}

	token, err := ca.signJWTSVID(jwtKey, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT SVID: %w", err)
	}

	if err := ca.c.CredValidator.ValidateWorkloadJWTSVID(token, params.SPIFFEID); err != nil {
		return "", err
	}

	telemetry_server.IncrServerCASignJWTSVIDCounter(ca.c.Metrics)
	return token, nil
}

func (ca *CA) getX509CA() (*X509CA, []*x509.Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.x509CA == nil {
		return nil, nil, errors.New("X509 CA is not available for signing")
	}
	return ca.x509CA, ca.x509CAChain, nil
}

func (ca *CA) signX509SVID(x509CA *X509CA, template *x509.Certificate) ([]*x509.Certificate, error) {
	x509SVID, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign X509 SVID: %w", err)
	}
	telemetry_server.IncrServerCASignX509Counter(ca.c.Metrics)
	return makeCertChain(x509CA, x509SVID), nil
}

func (ca *CA) signJWTSVID(jwtKey *JWTKey, claims map[string]interface{}) (string, error) {
	alg, err := cryptoutil.JoseAlgFromPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to determine JWT key algorithm: %w", err)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(jwtKey.Signer),
				KeyID: jwtKey.Kid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure JWT signer: %w", err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT SVID: %w", err)
	}

	return signedToken, nil
}

func makeCertChain(x509CA *X509CA, leaf *x509.Certificate) []*x509.Certificate {
	return append([]*x509.Certificate{leaf}, x509CA.UpstreamChain...)
}
