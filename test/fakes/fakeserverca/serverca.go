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

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/ca"
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

type ServerCA struct {
	trustDomain string
	defaultTTL  time.Duration
	nowFn       func() time.Time
	sn          int64
	key         crypto.PrivateKey
	cert        *x509.Certificate
}

func New(t *testing.T, trustDomain string, nowFn func() time.Time, defaultTTL time.Duration) *ServerCA {
	if nowFn == nil {
		nowFn = time.Now
	}

	key, err := pemutil.ParseECPrivateKey(keyPEM)
	require.NoError(t, err)

	now := nowFn()
	cert, err := ca.SelfSignServerCACertificate(
		key, trustDomain, pkix.Name{CommonName: "FAKE SERVER CA"},
		now, now.Add(time.Hour))
	require.NoError(t, err)

	return &ServerCA{
		trustDomain: trustDomain,
		defaultTTL:  defaultTTL,
		nowFn:       nowFn,
		key:         key,
		cert:        cert,
	}
}

func (c *ServerCA) SignX509SVID(ctx context.Context, csrDER []byte, ttl time.Duration) (*x509.Certificate, error) {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	now := c.nowFn()
	c.sn++
	template, err := ca.CreateX509SVIDTemplate(csrDER, c.trustDomain, now, now.Add(ttl), big.NewInt(c.sn))
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.cert, template.PublicKey, c.key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
