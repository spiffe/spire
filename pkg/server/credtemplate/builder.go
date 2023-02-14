package credtemplate

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	// DefaultX509CATTL is the TTL given to X509 CAs if not overridden by
	// the server config.
	DefaultX509CATTL = time.Hour * 24

	// DefaultX509SVIDTTL is the TTL given to X509 SVIDs if not overridden by
	// the server config.
	DefaultX509SVIDTTL = time.Hour

	// DefaultJWTSVIDTTL is the TTL given to JWT SVIDs if a different TTL is
	// not provided in the signing request.
	DefaultJWTSVIDTTL = time.Minute * 5

	// NotBeforeCushion is how much of a cushion to subtract from the current
	// time when determining the notBefore field of certificates to account
	// for clock skew.
	NotBeforeCushion = 10 * time.Second
)

// DefaultX509CASubject is the default subject set on workload X509SVIDs
// TODO: This is a historic, but poor, default. We should revisit (see issue #3841).
func DefaultX509CASubject() pkix.Name {
	return pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIFFE"},
	}
}

// DefaultX509SVIDSubject is the default subject set on workload X509SVIDs
// TODO: This is a historic, but poor, default. We should revisit (see issue #3841).
func DefaultX509SVIDSubject() pkix.Name {
	return pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
}

type SelfSignedX509CAParams struct {
	PublicKey crypto.PublicKey
}

type UpstreamSignedX509CAParams struct {
	PublicKey crypto.PublicKey
}

type DownstreamX509CAParams struct {
	ParentChain []*x509.Certificate
	PublicKey   crypto.PublicKey
	TTL         time.Duration
}

type ServerX509SVIDParams struct {
	ParentChain []*x509.Certificate
	PublicKey   crypto.PublicKey
}

type AgentX509SVIDParams struct {
	ParentChain []*x509.Certificate
	PublicKey   crypto.PublicKey
	SPIFFEID    spiffeid.ID
}

type WorkloadX509SVIDParams struct {
	ParentChain []*x509.Certificate
	PublicKey   crypto.PublicKey
	SPIFFEID    spiffeid.ID
	DNSNames    []string
	TTL         time.Duration
	Subject     pkix.Name
}

type WorkloadJWTSVIDParams struct {
	SPIFFEID      spiffeid.ID
	Audience      []string
	TTL           time.Duration
	ExpirationCap time.Time
}

type Config struct {
	TrustDomain         spiffeid.TrustDomain
	Clock               clock.Clock
	X509CASubject       pkix.Name
	X509CATTL           time.Duration
	X509SVIDSubject     pkix.Name
	X509SVIDTTL         time.Duration
	JWTSVIDTTL          time.Duration
	JWTIssuer           string
	AgentSVIDTTL        time.Duration
	CredentialComposers []credentialcomposer.CredentialComposer
	NewSerialNumber     func() (*big.Int, error)
}

type Builder struct {
	config Config

	x509CAID spiffeid.ID
	serverID spiffeid.ID
}

func NewBuilder(config Config) (*Builder, error) {
	if config.TrustDomain.IsZero() {
		return nil, errors.New("trust domain must be set")
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	if config.X509CASubject.String() == "" {
		config.X509CASubject = DefaultX509CASubject()
	}
	if config.X509CATTL == 0 {
		config.X509CATTL = DefaultX509CATTL
	}
	if config.X509SVIDSubject.String() == "" {
		config.X509SVIDSubject = DefaultX509SVIDSubject()
	}
	if config.X509SVIDTTL == 0 {
		config.X509SVIDTTL = DefaultX509SVIDTTL
	}
	if config.JWTSVIDTTL == 0 {
		config.JWTSVIDTTL = DefaultJWTSVIDTTL
	}
	if config.AgentSVIDTTL == 0 {
		// config.X509SVIDTTL should be initialized by the code above and
		// therefore safe to use to initialize the AgentSVIDTTL.
		config.AgentSVIDTTL = config.X509SVIDTTL
	}
	if config.NewSerialNumber == nil {
		config.NewSerialNumber = x509util.NewSerialNumber
	}

	serverID, err := idutil.ServerID(config.TrustDomain)
	if err != nil {
		// This check is purely defensive; idutil.ServerID should not fail since the trust domain is valid.
		return nil, err
	}

	return &Builder{
		config:   config,
		x509CAID: config.TrustDomain.ID(),
		serverID: serverID,
	}, nil
}

func (b *Builder) Config() Config {
	return b.config
}

func (b *Builder) BuildSelfSignedX509CATemplate(ctx context.Context, params SelfSignedX509CAParams) (*x509.Certificate, error) {
	tmpl, err := b.buildX509CATemplate(params.PublicKey, nil, 0)
	if err != nil {
		return nil, err
	}

	for _, cc := range b.config.CredentialComposers {
		attributes, err := cc.ComposeServerX509CA(ctx, x509CAAttributesFromTemplate(tmpl))
		if err != nil {
			return nil, err
		}
		applyX509CAAttributes(tmpl, attributes)
	}

	return tmpl, nil
}

func (b *Builder) BuildUpstreamSignedX509CACSR(ctx context.Context, params UpstreamSignedX509CAParams) (*x509.CertificateRequest, error) {
	tmpl, err := b.buildX509CATemplate(params.PublicKey, nil, 0)
	if err != nil {
		return nil, err
	}

	for _, cc := range b.config.CredentialComposers {
		attributes, err := cc.ComposeServerX509CA(ctx, x509CAAttributesFromTemplate(tmpl))
		if err != nil {
			return nil, err
		}
		applyX509CAAttributes(tmpl, attributes)
	}

	// Create the CertificateRequest from the Certificate template. The
	// PolicyIdentifiers field is ignored since that can be applied by the
	// upstream signer and isn't a part of the native CertificateRequest type.
	// TODO: maybe revisit this if needed and embed the policy identifiers in
	// the extra extensions.
	return &x509.CertificateRequest{
		Subject:         tmpl.Subject,
		ExtraExtensions: tmpl.ExtraExtensions,
		URIs:            tmpl.URIs,
		PublicKey:       tmpl.PublicKey,
	}, nil
}

func (b *Builder) BuildDownstreamX509CATemplate(ctx context.Context, params DownstreamX509CAParams) (*x509.Certificate, error) {
	if len(params.ParentChain) == 0 {
		return nil, errors.New("parent chain required to build downstream X509 CA template")
	}

	tmpl, err := b.buildX509CATemplate(params.PublicKey, params.ParentChain, params.TTL)
	if err != nil {
		return nil, err
	}
	tmpl.Subject = params.ParentChain[0].Subject
	tmpl.Subject.OrganizationalUnit = []string{fmt.Sprintf("DOWNSTREAM-%d", len(params.ParentChain))}

	// It's a bit gross, but SPIRE has historically signed downstream X509CA's with the X509-SVID ttl, so
	// let's override the NotBefore/NotAfter fields set by buildX509CATemplate.
	tmpl.NotBefore, tmpl.NotAfter = b.computeX509SVIDLifetime(params.ParentChain, params.TTL)

	for _, cc := range b.config.CredentialComposers {
		attributes, err := cc.ComposeServerX509CA(ctx, x509CAAttributesFromTemplate(tmpl))
		if err != nil {
			return nil, err
		}
		applyX509CAAttributes(tmpl, attributes)
	}

	return tmpl, nil
}

func (b *Builder) BuildServerX509SVIDTemplate(ctx context.Context, params ServerX509SVIDParams) (*x509.Certificate, error) {
	tmpl, err := b.buildX509SVIDTemplate(b.serverID, params.PublicKey, params.ParentChain, pkix.Name{}, 0)
	if err != nil {
		return nil, err
	}

	for _, cc := range b.config.CredentialComposers {
		attributes, err := cc.ComposeServerX509SVID(ctx, x509SVIDAttributesFromTemplate(tmpl))
		if err != nil {
			return nil, err
		}
		applyX509SVIDAttributes(tmpl, attributes)
	}

	return tmpl, nil
}

func (b *Builder) BuildAgentX509SVIDTemplate(ctx context.Context, params AgentX509SVIDParams) (*x509.Certificate, error) {
	tmpl, err := b.buildX509SVIDTemplate(params.SPIFFEID, params.PublicKey, params.ParentChain, pkix.Name{}, b.config.AgentSVIDTTL)
	if err != nil {
		return nil, err
	}

	for _, cc := range b.config.CredentialComposers {
		attributes, err := cc.ComposeAgentX509SVID(ctx, params.SPIFFEID, params.PublicKey, x509SVIDAttributesFromTemplate(tmpl))
		if err != nil {
			return nil, err
		}
		applyX509SVIDAttributes(tmpl, attributes)
	}

	return tmpl, nil
}

func (b *Builder) BuildWorkloadX509SVIDTemplate(ctx context.Context, params WorkloadX509SVIDParams) (*x509.Certificate, error) {
	subject := b.config.X509SVIDSubject
	if params.Subject.String() != "" {
		subject = params.Subject
	}

	tmpl, err := b.buildX509SVIDTemplate(params.SPIFFEID, params.PublicKey, params.ParentChain, subject, params.TTL)
	if err != nil {
		return nil, err
	}

	// The first DNS name is also added as the CN by default. This happens
	// even if the subject is provided explicitly in the params for backwards
	// compatibility. Ideally we wouldn't do override the subject in this
	// case. It is still overridable via the credential composers however.
	if len(params.DNSNames) > 0 {
		tmpl.Subject.CommonName = params.DNSNames[0]
		tmpl.DNSNames = params.DNSNames
	}

	for _, cc := range b.config.CredentialComposers {
		attributes, err := cc.ComposeWorkloadX509SVID(ctx, params.SPIFFEID, params.PublicKey, x509SVIDAttributesFromTemplate(tmpl))
		if err != nil {
			return nil, err
		}
		applyX509SVIDAttributes(tmpl, attributes)
	}

	return tmpl, nil
}

func (b *Builder) BuildWorkloadJWTSVIDClaims(ctx context.Context, params WorkloadJWTSVIDParams) (map[string]interface{}, error) {
	params.Audience = dropEmptyValues(params.Audience)

	if params.SPIFFEID.IsZero() {
		return nil, errors.New("invalid JWT-SVID ID: cannot be empty")
	}
	if err := api.VerifyTrustDomainMemberID(b.config.TrustDomain, params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid JWT-SVID ID: %w", err)
	}
	if len(params.Audience) == 0 {
		return nil, errors.New("invalid JWT-SVID audience: cannot be empty")
	}

	now := b.config.Clock.Now()

	ttl := params.TTL
	if ttl <= 0 {
		ttl = b.config.JWTSVIDTTL
	}
	_, expiresAt := computeCappedLifetime(b.config.Clock, ttl, params.ExpirationCap)

	attributes := credentialcomposer.JWTSVIDAttributes{
		Claims: map[string]interface{}{
			"sub": params.SPIFFEID.String(),
			"exp": jwt.NewNumericDate(expiresAt),
			"aud": params.Audience,
			"iat": jwt.NewNumericDate(now),
		},
	}
	if b.config.JWTIssuer != "" {
		attributes.Claims["iss"] = b.config.JWTIssuer
	}

	for _, cc := range b.config.CredentialComposers {
		var err error
		attributes, err = cc.ComposeWorkloadJWTSVID(ctx, params.SPIFFEID, attributes)
		if err != nil {
			return nil, err
		}
	}

	return attributes.Claims, nil
}

func (b *Builder) buildX509CATemplate(publicKey crypto.PublicKey, parentChain []*x509.Certificate, ttl time.Duration) (*x509.Certificate, error) {
	tmpl, err := b.buildBaseTemplate(b.x509CAID, publicKey, parentChain)
	if err != nil {
		return nil, err
	}

	tmpl.Subject = b.config.X509CASubject
	tmpl.NotBefore, tmpl.NotAfter = b.computeX509CALifetime(parentChain, ttl)
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	tmpl.IsCA = true

	return tmpl, nil
}

func (b *Builder) buildX509SVIDTemplate(spiffeID spiffeid.ID, publicKey crypto.PublicKey, parentChain []*x509.Certificate, subject pkix.Name, ttl time.Duration) (*x509.Certificate, error) {
	if len(parentChain) == 0 {
		return nil, errors.New("parent chain required to build X509-SVID template")
	}
	if spiffeID.IsZero() {
		return nil, errors.New("invalid X509-SVID ID: cannot be empty")
	}
	if err := api.VerifyTrustDomainMemberID(b.config.TrustDomain, spiffeID); err != nil {
		return nil, fmt.Errorf("invalid X509-SVID ID: %w", err)
	}

	tmpl, err := b.buildBaseTemplate(spiffeID, publicKey, parentChain)
	if err != nil {
		return nil, err
	}

	tmpl.Subject = b.config.X509SVIDSubject
	if subject.String() != "" {
		tmpl.Subject = subject
	}

	tmpl.NotBefore, tmpl.NotAfter = b.computeX509SVIDLifetime(parentChain, ttl)
	tmpl.KeyUsage = x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}

	// Append the unique ID to the subject, unless disabled
	tmpl.Subject.ExtraNames = append(tmpl.Subject.ExtraNames, x509svid.UniqueIDAttribute(spiffeID))

	return tmpl, nil
}

func (b *Builder) buildBaseTemplate(spiffeID spiffeid.ID, publicKey crypto.PublicKey, parentChain []*x509.Certificate) (*x509.Certificate, error) {
	serialNumber, err := b.config.NewSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to get new serial number: %w", err)
	}

	subjectKeyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	// Explicitly set the AKI on the signed certificate, otherwise it won't be
	// added if the subject and issuer match (however unlikely).
	var authorityKeyID []byte
	if len(parentChain) > 0 {
		authorityKeyID = parentChain[0].SubjectKeyId
	}

	return &x509.Certificate{
		SerialNumber:          serialNumber,
		URIs:                  []*url.URL{spiffeID.URL()},
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        authorityKeyID,
		BasicConstraintsValid: true,
		PublicKey:             publicKey,
	}, nil
}

func (b *Builder) computeX509CALifetime(parentChain []*x509.Certificate, ttl time.Duration) (notBefore, notAfter time.Time) {
	if ttl <= 0 {
		ttl = b.config.X509CATTL
	}
	return computeCappedLifetime(b.config.Clock, ttl, parentChainExpiration(parentChain))
}

func (b *Builder) computeX509SVIDLifetime(parentChain []*x509.Certificate, ttl time.Duration) (notBefore, notAfter time.Time) {
	if ttl <= 0 {
		ttl = b.config.X509SVIDTTL
	}
	return computeCappedLifetime(b.config.Clock, ttl, parentChainExpiration(parentChain))
}

func x509CAAttributesFromTemplate(tmpl *x509.Certificate) credentialcomposer.X509CAAttributes {
	return credentialcomposer.X509CAAttributes{
		Subject:           tmpl.Subject,
		PolicyIdentifiers: tmpl.PolicyIdentifiers,
		ExtraExtensions:   tmpl.ExtraExtensions,
	}
}
func x509SVIDAttributesFromTemplate(tmpl *x509.Certificate) credentialcomposer.X509SVIDAttributes {
	return credentialcomposer.X509SVIDAttributes{
		Subject:         tmpl.Subject,
		DNSNames:        tmpl.DNSNames,
		ExtraExtensions: tmpl.ExtraExtensions,
	}
}

func applyX509CAAttributes(tmpl *x509.Certificate, attribs credentialcomposer.X509CAAttributes) {
	tmpl.Subject = attribs.Subject
	tmpl.PolicyIdentifiers = attribs.PolicyIdentifiers
	tmpl.ExtraExtensions = attribs.ExtraExtensions
}

func applyX509SVIDAttributes(tmpl *x509.Certificate, attribs credentialcomposer.X509SVIDAttributes) {
	tmpl.Subject = attribs.Subject
	tmpl.DNSNames = attribs.DNSNames
	tmpl.ExtraExtensions = attribs.ExtraExtensions
}

func computeCappedLifetime(clk clock.Clock, ttl time.Duration, expirationCap time.Time) (notBefore, notAfter time.Time) {
	now := clk.Now()
	notBefore = now.Add(-NotBeforeCushion)
	notAfter = now.Add(ttl)
	if !expirationCap.IsZero() && notAfter.After(expirationCap) {
		notAfter = expirationCap
	}
	return notBefore, notAfter
}

func parentChainExpiration(parentChain []*x509.Certificate) time.Time {
	var expiration time.Time
	if len(parentChain) > 0 && !parentChain[0].NotAfter.IsZero() {
		expiration = parentChain[0].NotAfter
	}
	return expiration
}

func dropEmptyValues(ss []string) []string {
	next := 0
	for _, s := range ss {
		if s != "" {
			ss[next] = s
			next++
		}
	}
	ss = ss[:next]
	return ss
}
