package fakeserverca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
)

var (
	signer, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`))

	subject = pkix.Name{CommonName: "FAKE SERVER CA"}
)

type Options struct {
	Clock          clock.Clock
	X509SVIDTTL    time.Duration
	JWTSVIDTTL     time.Duration
	UpstreamCA     upstreamca.UpstreamCA
	UpstreamBundle bool
}

type CA struct {
	*ca.CA
	options *Options
	bundle  []*x509.Certificate
}

func New(t *testing.T, trustDomain string, options *Options) *CA {
	if options == nil {
		options = new(Options)
	}
	if options.Clock == nil {
		options.Clock = clock.New()
	}
	if options.X509SVIDTTL == 0 {
		options.X509SVIDTTL = time.Minute
	}
	if options.JWTSVIDTTL == 0 {
		options.JWTSVIDTTL = time.Minute
	}

	log, _ := test.NewNullLogger()

	notBefore := options.Clock.Now()
	notAfter := notBefore.Add(time.Hour)

	var x509CA *ca.X509CA
	var bundle []*x509.Certificate
	var err error
	if options.UpstreamCA != nil {
		x509CA, bundle, err = ca.UpstreamSignX509CA(context.Background(), signer, trustDomain, subject, options.UpstreamCA, options.UpstreamBundle, 0)
	} else {
		x509CA, bundle, err = ca.SelfSignX509CA(context.Background(), signer, trustDomain, subject, notBefore, notAfter)
	}
	require.NoError(t, err)

	serverCA := ca.NewCA(ca.CAConfig{
		Log:         log,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: url.URL{Scheme: "spiffe", Host: trustDomain},
		X509SVIDTTL: options.X509SVIDTTL,
		JWTSVIDTTL:  options.JWTSVIDTTL,
		Clock:       options.Clock,
	})
	serverCA.SetX509CA(x509CA)
	serverCA.SetJWTKey(&ca.JWTKey{
		Signer:   signer,
		Kid:      "KID",
		NotAfter: notAfter,
	})

	return &CA{
		CA:      serverCA,
		options: options,
		bundle:  bundle,
	}
}

func (c *CA) Bundle() []*x509.Certificate {
	return c.bundle
}

func (c *CA) Clock() clock.Clock {
	return c.options.Clock
}

func (c *CA) X509SVIDTTL() time.Duration {
	return c.options.X509SVIDTTL
}

func (c *CA) JWTSVIDTTL() time.Duration {
	return c.options.JWTSVIDTTL
}
