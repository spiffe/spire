package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/api/node"
)

const (
	DefaultJWTSVIDTTL = time.Minute * 5
)

type serverCAConfig struct {
	Log         logrus.FieldLogger
	Catalog     catalog.Catalog
	TrustDomain url.URL
	DefaultTTL  time.Duration
}

type ServerCA interface {
	SignX509SVID(ctx context.Context, csrDER []byte, ttl time.Duration) ([]*x509.Certificate, error)
	SignJWTSVID(ctx context.Context, jsr *node.JSR) (string, error)
}

type serverCA struct {
	c      serverCAConfig
	x509sn int64

	mu sync.RWMutex
	kp *keypairSet

	hooks struct {
		now func() time.Time
	}
}

func newServerCA(config serverCAConfig) *serverCA {
	out := &serverCA{
		c: config,
	}
	out.hooks.now = time.Now
	return out
}

func (ca *serverCA) setKeypairSet(kp keypairSet) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	ca.kp = &kp
}

func (ca *serverCA) getKeypairSet() *keypairSet {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.kp
}

func (ca *serverCA) SignX509SVID(ctx context.Context, csrDER []byte, ttl time.Duration) ([]*x509.Certificate, error) {
	kp := ca.getKeypairSet()
	if kp == nil || kp.x509CA == nil || kp.x509CA.cert == nil {
		return nil, errors.New("no X509-SVID keypair available")
	}

	now := ca.hooks.now()
	if ttl <= 0 {
		ttl = ca.c.DefaultTTL
	}
	notBefore := now.Add(-backdate)
	notAfter := now.Add(ttl)
	if notAfter.After(kp.x509CA.cert.NotAfter) {
		notAfter = kp.x509CA.cert.NotAfter
	}

	serialNumber := big.NewInt(atomic.AddInt64(&ca.x509sn, 1))

	template, err := CreateX509SVIDTemplate(csrDER, ca.c.TrustDomain.Host, notBefore, notAfter, serialNumber)
	if err != nil {
		return nil, err
	}

	km := ca.c.Catalog.KeyManagers()[0]
	cert, err := x509util.CreateCertificate(ctx, km, template, kp.x509CA.cert, kp.X509CAKeyID(), template.PublicKey)
	if err != nil {
		return nil, err
	}

	ca.c.Log.Debugf("Signed x509 SVID %q (expires %s)", cert.URIs[0].String(), cert.NotAfter.Format(time.RFC3339))

	// build and return the certificate chain, starting with the newly signed cert and any
	// intermediates back to the signing root of the keypair. the keypair chain
	// is a full chain from the ca back to the signing root, so all but the
	// last element (i.e., the signing root) form the list of intermediates.
	return append([]*x509.Certificate{cert}, kp.x509CA.chain[:len(kp.x509CA.chain)-1]...), nil
}

func (ca *serverCA) SignJWTSVID(ctx context.Context, jsr *node.JSR) (string, error) {
	kp := ca.getKeypairSet()
	if kp == nil {
		return "", errors.New("no JWT-SVID keypair available")
	}

	if err := idutil.ValidateSpiffeID(jsr.SpiffeId, idutil.AllowTrustDomainWorkload(ca.c.TrustDomain.Host)); err != nil {
		return "", err
	}

	ttl := time.Duration(jsr.Ttl) * time.Second
	if ttl <= 0 {
		ttl = DefaultJWTSVIDTTL
	}
	expiresAt := ca.hooks.now().Add(ttl)
	if expiresAt.After(kp.jwtSigningKey.notAfter) {
		expiresAt = kp.jwtSigningKey.notAfter
	}

	km := ca.c.Catalog.KeyManagers()[0]
	signer := cryptoutil.NewKeyManagerSigner(km, kp.JWTSignerKeyID(), kp.jwtSigningKey.publicKey)
	token, err := jwtsvid.SignToken(jsr.SpiffeId, jsr.Audience, expiresAt, signer, kp.jwtSigningKey.Kid)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT-SVID: %v", err)
	}
	return token, nil
}
