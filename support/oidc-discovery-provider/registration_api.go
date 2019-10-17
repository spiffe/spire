package main

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"gopkg.in/square/go-jose.v2"
)

const (
	DefaultRegistrationAPIPollInterval = time.Second * 10
)

type RegistrationAPISourceConfig struct {
	Log          logrus.FieldLogger
	SocketPath   string
	PollInterval time.Duration
	Clock        clock.Clock
}

type RegistrationAPISource struct {
	log    logrus.FieldLogger
	clock  clock.Clock
	cancel context.CancelFunc

	mu      sync.RWMutex
	wg      sync.WaitGroup
	bundle  *common.Bundle
	jwks    *jose.JSONWebKeySet
	modTime time.Time
}

func NewRegistrationAPISource(config RegistrationAPISourceConfig) (*RegistrationAPISource, error) {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultRegistrationAPIPollInterval
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	conn, err := grpc.Dial("unix://"+config.SocketPath, grpc.WithInsecure())
	if err != nil {
		return nil, errs.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &RegistrationAPISource{
		log:    config.Log,
		clock:  config.Clock,
		cancel: cancel,
	}

	go s.pollEvery(ctx, conn, config.PollInterval)
	return s, nil
}

func (s *RegistrationAPISource) Close() error {
	s.cancel()
	s.wg.Wait()
	return nil
}

func (s *RegistrationAPISource) FetchKeySet() (*jose.JSONWebKeySet, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.jwks == nil {
		return nil, time.Time{}, false
	}
	return s.jwks, s.modTime, true
}

func (s *RegistrationAPISource) pollEvery(ctx context.Context, conn *grpc.ClientConn, interval time.Duration) {
	s.wg.Add(1)
	defer s.wg.Done()

	defer conn.Close()
	client := registration.NewRegistrationClient(conn)

	s.log.WithField("interval", interval).Debug("Polling started")
	for {
		s.pollOnce(ctx, client)
		select {
		case <-ctx.Done():
			s.log.Debug("Polling done: %v", ctx.Err())
			return
		case <-s.clock.After(interval):
		}
	}
}

func (s *RegistrationAPISource) pollOnce(ctx context.Context, client registration.RegistrationClient) {
	// Ensure the stream gets cleaned up
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resp, err := client.FetchBundle(ctx, &common.Empty{})
	if err != nil {
		s.log.WithError(err).Warn("Failed to fetch bundle")
		return
	}

	s.parseBundle(resp.Bundle)
}

func (s *RegistrationAPISource) parseBundle(bundle *common.Bundle) {
	if bundle == nil {
		s.log.Error("Received an empty bundle from the Registration API")
		return
	}

	// If the bundle hasn't changed, don't bother continuing
	s.mu.RLock()
	if s.bundle != nil && proto.Equal(s.bundle, bundle) {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	jwks := new(jose.JSONWebKeySet)
	for _, key := range bundle.JwtSigningKeys {
		publicKey, err := x509.ParsePKIXPublicKey(key.PkixBytes)
		if err != nil {
			s.log.WithError(err).WithField("kid", key.Kid).Warn("Malformed public key in bundle")
			continue
		}

		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   publicKey,
			KeyID: key.Kid,
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = bundle
	s.jwks = jwks
	s.modTime = s.clock.Now()
}
