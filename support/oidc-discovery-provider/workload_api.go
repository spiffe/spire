package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
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

	mu        sync.RWMutex
	wg        sync.WaitGroup
	rawBundle []byte
	jwks      *jose.JSONWebKeySet
	modTime   time.Time
	pollTime  time.Time
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
			return nil, errs.Wrap(err)
		}
		opts = append(opts, o)
	}

	trustDomain, err := spiffeid.TrustDomainFromString(config.TrustDomain)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	client, err := workloadapi.New(context.Background(), opts...)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &WorkloadAPISource{
		log:         config.Log,
		clock:       config.Clock,
		cancel:      cancel,
		trustDomain: trustDomain,
	}

	go s.pollEvery(ctx, client, config.PollInterval)
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

func (s *WorkloadAPISource) LastSuccessfulPoll() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pollTime
}

func (s *WorkloadAPISource) pollEvery(ctx context.Context, client *workloadapi.Client, interval time.Duration) {
	s.wg.Add(1)
	defer s.wg.Done()

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
