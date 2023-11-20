package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"gopkg.in/square/go-jose.v2"
)

const (
	DefaultServerAPIPollInterval = time.Second * 10
	// DefaultServerSVIDTTL is zero indicates the default SVID TTL is determined
	// by the Spire server instead of oidc-provider
	DefaultServerSVIDTTL = 0
)

var (
	_ JWKSSource        = &ServerAPISource{}
	_ x509svid.Source   = &ServerAPISource{}
	_ x509bundle.Source = &ServerAPISource{}
)

type ServerAPISourceConfig struct {
	Log          logrus.FieldLogger
	GRPCTarget   string
	PollInterval time.Duration
	SVIDTTL      time.Duration
	Clock        clock.Clock
	DNSNames     []string
	SPIFFEID     string
}

type ServerAPISource struct {
	log    logrus.FieldLogger
	clock  clock.Clock
	cancel context.CancelFunc

	mu         sync.RWMutex
	wg         sync.WaitGroup
	conn       *grpc.ClientConn
	bundle     *types.Bundle
	x509bundle *x509bundle.Bundle
	jwks       *jose.JSONWebKeySet
	mint       *x509svid.SVID
	modTime    time.Time
	pollTime   time.Time
	expireAt   time.Time
	rotatedAt  time.Time

	dnsNames []string
	interval time.Duration
	svidTTL  time.Duration
	spiffeid spiffeid.ID
}

func NewServerAPISource(config ServerAPISourceConfig) (*ServerAPISource, error) {
	var id spiffeid.ID
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultServerAPIPollInterval
	}
	if config.SVIDTTL <= 0 {
		config.SVIDTTL = DefaultServerSVIDTTL
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	conn, err := util.GRPCDialContext(context.Background(), config.GRPCTarget)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	if config.SPIFFEID != "" {
		id, err = spiffeid.FromString(config.SPIFFEID)
		if err != nil {
			return nil, errs.Wrap(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &ServerAPISource{
		log:      config.Log,
		clock:    config.Clock,
		cancel:   cancel,
		conn:     conn,
		dnsNames: config.DNSNames,
		interval: config.PollInterval,
		svidTTL:  config.SVIDTTL,
		spiffeid: id,
	}

	go s.pollEvery(ctx, conn, config.PollInterval)
	return s, nil
}

func (s *ServerAPISource) Close() error {
	s.cancel()
	s.wg.Wait()
	s.conn.Close()
	return nil
}

func (s *ServerAPISource) FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.jwks == nil {
		return nil, time.Time{}, false
	}
	return s.jwks, s.modTime, true
}

func (s *ServerAPISource) LastSuccessfulPoll() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pollTime
}

func (s *ServerAPISource) pollEvery(ctx context.Context, conn *grpc.ClientConn, interval time.Duration) {
	s.wg.Add(1)
	defer s.wg.Done()

	bundle := bundlev1.NewBundleClient(conn)
	svid := svidv1.NewSVIDClient(conn)

	s.log.WithField("interval", interval).Debug("Polling started")
	for {
		s.pollOnce(ctx, bundle, svid)
		select {
		case <-ctx.Done():
			s.log.WithError(ctx.Err()).Debug("Polling done")
			return
		case <-s.clock.After(interval):
		}
	}
}

func (s *ServerAPISource) pollOnce(ctx context.Context, client bundlev1.BundleClient, svid svidv1.SVIDClient) {
	// Ensure the stream gets cleaned up
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bundle, err := client.GetBundle(ctx, &bundlev1.GetBundleRequest{
		OutputMask: &types.BundleMask{
			JwtAuthorities:  true,
			X509Authorities: true,
		},
	})
	if err != nil {
		s.log.WithError(err).Warn("Failed to fetch bundle")
		return
	}

	s.parseBundle(bundle)
	s.mu.Lock()
	s.pollTime = s.clock.Now()
	s.mu.Unlock()

	if s.needMintX509SVID() {
		if err := s.mintX509SVID(ctx, svid, s.spiffeid, s.dnsNames, s.svidTTL); err != nil {
			s.log.WithError(err).Warn("Failed to mint x509 svid")
			return
		}
		s.log.WithField("id", s.spiffeid).WithField("dnsNames", s.dnsNames).WithField("ttl", s.svidTTL).Info("Minted x509 svid")
	}
}

func (s *ServerAPISource) parseBundle(bundle *types.Bundle) {
	// If the bundle hasn't changed, don't bother continuing
	s.mu.RLock()
	if s.bundle != nil && proto.Equal(s.bundle, bundle) {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	jwks := new(jose.JSONWebKeySet)
	for _, key := range bundle.JwtAuthorities {
		publicKey, err := x509.ParsePKIXPublicKey(key.PublicKey)
		if err != nil {
			s.log.WithError(err).WithField("kid", key.KeyId).Warn("Malformed public key in bundle")
			continue
		}

		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   publicKey,
			KeyID: key.KeyId,
		})
	}

	var x509b *x509bundle.Bundle
	td, err := spiffeid.TrustDomainFromString(bundle.TrustDomain)
	if err != nil {
		s.log.WithError(err).WithField("trustdomain", bundle.TrustDomain).Warn("Malformed trustdomain in bundle")
	} else {
		x509b = x509bundle.New(td)
		for _, au := range bundle.X509Authorities {
			cert, err := x509.ParseCertificates(au.Asn1)
			if err != nil {
				s.log.WithError(err).WithField("trustdomain", bundle.TrustDomain).Warn("Malformed certificate in bundle")
				continue
			}

			for _, c := range cert {
				x509b.AddX509Authority(c)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = bundle
	s.x509bundle = x509b
	s.jwks = jwks
	s.modTime = s.clock.Now()
}

func (s *ServerAPISource) needMintX509SVID() bool {
	var lifetime time.Duration
	var expiresIn time.Duration

	if s.spiffeid.IsZero() {
		return false
	}

	if !s.rotatedAt.IsZero() {
		lifetime = s.expireAt.Sub(s.rotatedAt)
		expiresIn = s.expireAt.Sub(s.clock.Now())
	}

	var reason string
	switch {
	case s.mint == nil:
		reason = "initializing"
	case lifetime == 0:
		reason = "initializing"
	case expiresSoon(lifetime, expiresIn):
		reason = "expires soon"
	case expiresIn < 0:
		reason = "has expired"
	default:
		return false
	}

	s.log.WithField("reason", reason).WithField("dnsNames", s.dnsNames).Info("Need mint x509 svid")
	return true
}

func (s *ServerAPISource) mintX509SVID(ctx context.Context, client svidv1.SVIDClient, mintID spiffeid.ID, dnsNames []string, ttl time.Duration) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate X509-SVID private key: %w", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: dnsNames,
		URIs:     []*url.URL{mintID.URL()},
	}, key)
	if err != nil {
		return fmt.Errorf("failed to create X509-SVID CSR: %w", err)
	}

	resp, err := client.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{
		Csr: csr,
		Ttl: int32(ttl.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("failed to mint X509-SVID: %w", err)
	}

	if resp.Svid == nil {
		return errors.New("no X509-SVID in response")
	}

	td, err := spiffeid.TrustDomainFromString(resp.Svid.Id.TrustDomain)
	if err != nil {
		return fmt.Errorf("invalid trust domain in response ID: %w", err)
	}

	id, err := spiffeid.FromPath(td, resp.Svid.Id.Path)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE ID in response: %w", err)
	}

	var certChain []*x509.Certificate
	for _, certDER := range resp.Svid.CertChain {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("invalid certificate in response: %w", err)
		}
		certChain = append(certChain, cert)
	}
	if len(certChain) == 0 {
		return errors.New("no certificates in response")
	}

	svid := &x509svid.SVID{
		ID:           id,
		PrivateKey:   key,
		Certificates: certChain,
	}
	expireAt := certChain[0].NotAfter

	for i, c := range certChain {
		s.log.WithField("Subject", c.Subject.String()).WithField("Issuer", c.Issuer.String()).Debugf("Minted x509 svid cert %d", i)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.mint = svid
	s.expireAt = expireAt
	s.rotatedAt = s.clock.Now()
	return nil
}

func (s *ServerAPISource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mint == nil {
		return nil, errors.New("X509 SVID is not ready")
	}
	return s.mint, nil
}

func (s *ServerAPISource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.x509bundle == nil {
		return nil, errors.New("X509 Bundle is not ready")
	}
	return s.x509bundle, nil
}

func expiresSoon(lifetime, expiresIn time.Duration) bool {
	const day = time.Hour * 24
	const week = day * 7
	const monthish = day * 30
	switch {
	case lifetime > monthish:
		return expiresIn < week
	case lifetime > week:
		return expiresIn < (week / 2)
	case lifetime > day:
		return expiresIn < (day / 2)
	case lifetime > time.Hour:
		return expiresIn < (time.Hour / 2)
	default:
		return expiresIn < (lifetime / 2)
	}
}
