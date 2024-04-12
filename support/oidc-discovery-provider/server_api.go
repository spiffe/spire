package main

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultServerAPIPollInterval = time.Second * 10
)

type ServerAPISourceConfig struct {
	Log          logrus.FieldLogger
	GRPCTarget   string
	PollInterval time.Duration
	Clock        clock.Clock
}

type ServerAPISource struct {
	log    logrus.FieldLogger
	clock  clock.Clock
	cancel context.CancelFunc

	mu       sync.RWMutex
	wg       sync.WaitGroup
	bundle   *types.Bundle
	jwks     *jose.JSONWebKeySet
	modTime  time.Time
	pollTime time.Time
}

func NewServerAPISource(config ServerAPISourceConfig) (*ServerAPISource, error) {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultServerAPIPollInterval
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	conn, err := util.GRPCDialContext(context.Background(), config.GRPCTarget)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &ServerAPISource{
		log:    config.Log,
		clock:  config.Clock,
		cancel: cancel,
	}

	go s.pollEvery(ctx, conn, config.PollInterval)
	return s, nil
}

func (s *ServerAPISource) Close() error {
	s.cancel()
	s.wg.Wait()
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

	defer conn.Close()
	client := bundlev1.NewBundleClient(conn)

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

func (s *ServerAPISource) pollOnce(ctx context.Context, client bundlev1.BundleClient) {
	// Ensure the stream gets cleaned up
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bundle, err := client.GetBundle(ctx, &bundlev1.GetBundleRequest{
		OutputMask: &types.BundleMask{
			JwtAuthorities: true,
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

	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = bundle
	s.jwks = jwks
	s.modTime = s.clock.Now()
}
