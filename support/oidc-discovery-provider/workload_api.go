package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
)

const (
	DefaultWorkloadAPIPollInterval = time.Second * 10
)

type WorkloadAPISourceConfig struct {
	Log          logrus.FieldLogger
	Addr         net.Addr
	TrustDomain  string
	PollInterval time.Duration
	Clock        clock.Clock
}

type WorkloadAPISource struct {
	log         logrus.FieldLogger
	clock       clock.Clock
	trustDomain spiffeid.TrustDomain
	cancel      context.CancelFunc

	mu           sync.RWMutex
	wg           sync.WaitGroup
	rawBundle    []byte
	jwks         *jose.JSONWebKeySet
	spiffeBundle *spiffebundle.Bundle
	modTime      time.Time
	pollTime     time.Time
}

func NewWorkloadAPISource(config WorkloadAPISourceConfig) (*WorkloadAPISource, error) {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultWorkloadAPIPollInterval
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	var opts []workloadapi.ClientOption
	if config.Addr != nil {
		o, err := util.GetWorkloadAPIClientOption(config.Addr)
		if err != nil {
			return nil, err
		}
		opts = append(opts, o)
	}

	trustDomain, err := spiffeid.TrustDomainFromString(config.TrustDomain)
	if err != nil {
		return nil, err
	}

	client, err := workloadapi.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &WorkloadAPISource{
		log:         config.Log,
		clock:       config.Clock,
		cancel:      cancel,
		trustDomain: trustDomain,
	}

	s.wg.Go(func() {
		s.pollEvery(ctx, client, config.PollInterval)
	})
	return s, nil
}

func (s *WorkloadAPISource) Close() error {
	s.cancel()
	s.wg.Wait()
	return nil
}

func (s *WorkloadAPISource) FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.jwks == nil {
		return nil, time.Time{}, false
	}
	return s.jwks, s.modTime, true
}

func (s *WorkloadAPISource) FetchBundle() (*spiffebundle.Bundle, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.spiffeBundle == nil {
		return nil, time.Time{}, false
	}
	return s.spiffeBundle, s.modTime, true
}

func (s *WorkloadAPISource) LastSuccessfulPoll() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pollTime
}

func (s *WorkloadAPISource) pollEvery(ctx context.Context, client *workloadapi.Client, interval time.Duration) {
	defer client.Close()

	s.log.WithField("interval", interval).Debug("Polling started")
	for {
		s.pollOnce(ctx, client)
		select {
		case <-ctx.Done():
			s.log.WithError(ctx.Err()).Debug("Polling done")
			return
		case <-s.clock.After(interval):
		}
	}
}

func (s *WorkloadAPISource) pollOnce(ctx context.Context, client *workloadapi.Client) {
	jwtBundles, err := client.FetchJWTBundles(ctx)
	if err != nil {
		s.log.WithError(err).Warn("Failed to fetch JWKS from the Workload API")
		return
	}

	jwtBundle, ok := jwtBundles.Get(s.trustDomain)
	if !ok {
		s.log.WithField(telemetry.TrustDomainID, s.trustDomain.IDString()).Error("No bundle for trust domain in Workload API response")
		return
	}

	// update pollTime when setJWKS was successful
	if s.setJWKS(jwtBundle) == nil {
		s.mu.Lock()
		s.pollTime = s.clock.Now()
		s.mu.Unlock()
	}

	// The X.509 authorities are only needed by the all-keys endpoint, so
	// failing to fetch them must not impact the JWKS served by the keys
	// endpoint. Keep serving the previously fetched trust bundle instead.
	x509Bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		s.log.WithError(err).Warn("Failed to fetch X.509 authorities from the Workload API")
		return
	}

	x509Bundle, ok := x509Bundles.Get(s.trustDomain)
	if !ok {
		s.log.WithField(telemetry.TrustDomainID, s.trustDomain.IDString()).Error("No X.509 bundle for trust domain in Workload API response")
		return
	}

	s.setBundle(jwtBundle, x509Bundle)
}

// setBundle combines the JWT and X.509 authorities fetched from the Workload
// API into the SPIFFE trust bundle served by the all-keys endpoint. The
// Workload API conveys neither a refresh hint nor a sequence number, so both
// are left unset and the refresh hint is derived when the bundle is served.
func (s *WorkloadAPISource) setBundle(jwtBundle *jwtbundle.Bundle, x509Bundle *x509bundle.Bundle) {
	bundle := spiffebundle.FromX509Bundle(x509Bundle)
	bundle.SetJWTAuthorities(jwtBundle.JWTAuthorities())

	s.mu.Lock()
	defer s.mu.Unlock()

	// If the bundle hasn't changed, don't bother continuing
	if s.spiffeBundle != nil && s.spiffeBundle.Equal(bundle) {
		return
	}
	s.spiffeBundle = bundle
	s.modTime = s.clock.Now()
}

func (s *WorkloadAPISource) setJWKS(bundle *jwtbundle.Bundle) error {
	rawBundle, err := bundle.Marshal()
	if err != nil {
		s.log.WithError(err).Error("Failed to marshal JWKS bundle received from the Workload API")
		return err
	}

	// If the bundle hasn't changed, don't bother continuing
	s.mu.RLock()
	unchanged := s.rawBundle != nil && bytes.Equal(s.rawBundle, rawBundle)
	s.mu.RUnlock()
	if unchanged {
		return nil
	}

	// Clean the JWKS
	jwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(rawBundle, jwks); err != nil {
		s.log.WithError(err).Error("Failed to parse trust domain bundle received from the Workload API")
		return err
	}
	for i, key := range jwks.Keys {
		key.Use = ""
		jwks.Keys[i] = key
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawBundle = rawBundle
	s.jwks = jwks
	s.modTime = s.clock.Now()

	return nil
}
