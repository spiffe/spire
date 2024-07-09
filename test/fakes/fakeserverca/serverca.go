package fakeserverca

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakehealthchecker"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var (
	signer = testkey.MustEC256()
)

type Options struct {
	Clock        clock.Clock
	AgentSVIDTTL time.Duration
	X509SVIDTTL  time.Duration
	JWTSVIDTTL   time.Duration
}

type CA struct {
	ca            *ca.CA
	credBuilder   *credtemplate.Builder
	credValidator *credvalidator.Validator
	options       *Options
	bundle        []*x509.Certificate
	err           error
}

func New(t *testing.T, trustDomain spiffeid.TrustDomain, options *Options) *CA {
	if options == nil {
		options = new(Options)
	}
	if options.Clock == nil {
		options.Clock = clock.NewMock(t)
	}
	if options.AgentSVIDTTL == 0 {
		options.AgentSVIDTTL = time.Minute
	}
	if options.X509SVIDTTL == 0 {
		options.X509SVIDTTL = time.Minute
	}
	if options.JWTSVIDTTL == 0 {
		options.JWTSVIDTTL = time.Minute
	}

	log, _ := test.NewNullLogger()

	healthChecker := fakehealthchecker.New()

	credBuilder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:  trustDomain,
		Clock:        options.Clock,
		X509CATTL:    time.Hour,
		AgentSVIDTTL: options.AgentSVIDTTL,
		X509SVIDTTL:  options.X509SVIDTTL,
		JWTSVIDTTL:   options.JWTSVIDTTL,
	})
	require.NoError(t, err)

	credValidator, err := credvalidator.New(credvalidator.Config{
		TrustDomain: trustDomain,
		Clock:       options.Clock,
	})
	require.NoError(t, err)

	serverCA := ca.NewCA(ca.Config{
		Log:           log,
		Metrics:       telemetry.Blackhole{},
		CredBuilder:   credBuilder,
		CredValidator: credValidator,
		TrustDomain:   trustDomain,
		HealthChecker: healthChecker,
	})

	template, err := credBuilder.BuildSelfSignedX509CATemplate(context.Background(), credtemplate.SelfSignedX509CAParams{
		PublicKey: signer.Public(),
	})
	require.NoError(t, err)

	caCert, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	require.NoError(t, err)

	serverCA.SetX509CA(&ca.X509CA{
		Signer:      signer,
		Certificate: caCert,
	})
	serverCA.SetJWTKey(&ca.JWTKey{
		Signer:   signer,
		Kid:      "KID",
		NotAfter: options.Clock.Now().Add(time.Hour),
	})

	return &CA{
		ca:            serverCA,
		credBuilder:   credBuilder,
		credValidator: credValidator,
		options:       options,
		bundle:        []*x509.Certificate{caCert},
	}
}

func (c *CA) CredBuilder() *credtemplate.Builder {
	return c.credBuilder
}

func (c *CA) CredValidator() *credvalidator.Validator {
	return c.credValidator
}

func (c *CA) SetX509CA(x509CA *ca.X509CA) {
	c.ca.SetX509CA(x509CA)
}

func (c *CA) SetJWTKey(jwtKey *ca.JWTKey) {
	c.ca.SetJWTKey(jwtKey)
}

func (c *CA) SignDownstreamX509CA(ctx context.Context, params ca.DownstreamX509CAParams) ([]*x509.Certificate, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.ca.SignDownstreamX509CA(ctx, params)
}

func (c *CA) SignServerX509SVID(ctx context.Context, params ca.ServerX509SVIDParams) ([]*x509.Certificate, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.ca.SignServerX509SVID(ctx, params)
}

func (c *CA) SignAgentX509SVID(ctx context.Context, params ca.AgentX509SVIDParams) ([]*x509.Certificate, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.ca.SignAgentX509SVID(ctx, params)
}

func (c *CA) SignWorkloadX509SVID(ctx context.Context, params ca.WorkloadX509SVIDParams) ([]*x509.Certificate, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.ca.SignWorkloadX509SVID(ctx, params)
}

func (c *CA) SignWorkloadJWTSVID(ctx context.Context, params ca.WorkloadJWTSVIDParams) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return c.ca.SignWorkloadJWTSVID(ctx, params)
}

func (c *CA) SetError(err error) {
	c.err = err
}

func (c *CA) Bundle() []*x509.Certificate {
	return c.bundle
}

func (c *CA) Clock() clock.Clock {
	return c.options.Clock
}

func (c *CA) X509CATTL() time.Duration {
	return time.Hour
}

func (c *CA) X509SVIDTTL() time.Duration {
	return c.options.X509SVIDTTL
}

func (c *CA) JWTSVIDTTL() time.Duration {
	return c.options.JWTSVIDTTL
}
