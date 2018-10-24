package fakeserverca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/stretchr/testify/require"
)

var (
	keyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`)
)

type Options struct {
	Now        func() time.Time
	DefaultTTL time.Duration
	UpstreamCA upstreamca.UpstreamCA
}

type ServerCA struct {
	trustDomain string
	sn          int64
	signer      crypto.Signer
	certs       []*x509.Certificate
	options     *Options
}

func New(t *testing.T, trustDomain string, options *Options) *ServerCA {
	if options == nil {
		options = new(Options)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.DefaultTTL == 0 {
		options.DefaultTTL = time.Minute
	}

	key, err := pemutil.ParseECPrivateKey(keyPEM)
	require.NoError(t, err)

	now := options.Now()
	subject := pkix.Name{CommonName: "FAKE SERVER CA"}
	var certs []*x509.Certificate
	if options.UpstreamCA != nil {
		cert, upstreamBundle, err := ca.UpstreamSignServerCACertificate(context.Background(), options.UpstreamCA, key, trustDomain, subject)
		require.NoError(t, err)
		certs = append(certs, cert)
		certs = append(certs, upstreamBundle...)
	} else {
		cert, err := ca.SelfSignServerCACertificate(
			key, trustDomain, subject,
			now, now.Add(time.Hour))
		require.NoError(t, err)
		certs = append(certs, cert)
	}

	return &ServerCA{
		trustDomain: trustDomain,
		signer:      key,
		certs:       certs,
		options:     options,
	}
}

func (c *ServerCA) SignX509SVID(ctx context.Context, csrDER []byte, ttl time.Duration) ([]*x509.Certificate, error) {
	if ttl <= 0 {
		ttl = c.options.DefaultTTL
	}
	now := c.options.Now()
	c.sn++
	template, err := ca.CreateX509SVIDTemplate(csrDER, c.trustDomain, now, now.Add(ttl), big.NewInt(c.sn))
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.certs[0], template.PublicKey, c.signer)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return append([]*x509.Certificate{cert}, c.certs[:len(c.certs)-1]...), nil
}

func (c *ServerCA) SignJWTSVID(ctx context.Context, jsr *node.JSR) (string, error) {
	ttl := time.Duration(jsr.Ttl) * time.Second
	if ttl <= 0 {
		ttl = c.options.DefaultTTL
	}
	expiresAt := time.Now().Add(ttl)
	return jwtsvid.SignToken(jsr.SpiffeId, jsr.Audience, expiresAt, c.signer, "fakekey")
}
