package main

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	DefaultFilePollInterval = time.Second * 10
)

type FileSourceConfig struct {
	Log          logrus.FieldLogger
	Path         string
	PollInterval time.Duration
	Clock        clock.Clock
}

type FileSource struct {
	log    logrus.FieldLogger
	clock  clock.Clock
	cancel context.CancelFunc

	mu       sync.RWMutex
	wg       sync.WaitGroup
	bundle   *spiffebundle.Bundle
	jwks     *jose.JSONWebKeySet
	modTime  time.Time
	pollTime time.Time
}

func NewFileSource(config FileSourceConfig) *FileSource {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultFilePollInterval
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &FileSource{
		log:    config.Log,
		clock:  config.Clock,
		cancel: cancel,
	}

	go s.pollEvery(ctx, config.Path, config.PollInterval)
	return s
}

func (s *FileSource) Close() error {
	s.cancel()
	s.wg.Wait()
	return nil
}

func (s *FileSource) FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.jwks == nil {
		return nil, time.Time{}, false
	}
	return s.jwks, s.modTime, true
}

func (s *FileSource) LastSuccessfulPoll() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pollTime
}

func (s *FileSource) pollEvery(ctx context.Context, path string, interval time.Duration) {
	s.wg.Add(1)
	defer s.wg.Done()

	s.log.WithField("interval", interval).Debug("Polling started")
	for {
		s.pollOnce(path)
		select {
		case <-ctx.Done():
			s.log.WithError(ctx.Err()).Debug("Polling done")
			return
		case <-s.clock.After(interval):
		}
	}
}

func (s *FileSource) pollOnce(path string) {
	bundle, err := spiffebundle.Load(spiffeid.TrustDomain{}, path)
	if err != nil {
		s.log.WithError(err).Warn("Failed to load SPIFFE trust bundle")
		return
	}

	s.parseBundle(bundle)
	s.mu.Lock()
	s.pollTime = s.clock.Now()
	s.mu.Unlock()
}

func (s *FileSource) parseBundle(bundle *spiffebundle.Bundle) {
	// If the bundle hasn't changed, don't bother continuing
	s.mu.RLock()
	if s.bundle != nil && s.bundle.Equal(bundle) {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	jwks := new(jose.JSONWebKeySet)
	for keyId, publicKey := range bundle.JWTAuthorities() {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   publicKey,
			KeyID: keyId,
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = bundle
	s.jwks = jwks
	s.modTime = s.clock.Now()
}
