package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	workload_pb "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/workload"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gopkg.in/square/go-jose.v2"
)

const (
	DefaultWorkloadAPIPollInterval = time.Second * 10
)

type WorkloadAPISourceConfig struct {
	Log          logrus.FieldLogger
	SocketPath   string
	TrustDomain  string
	PollInterval time.Duration
	Clock        clock.Clock
}

type WorkloadAPISource struct {
	log           logrus.FieldLogger
	clock         clock.Clock
	trustDomainID string
	cancel        context.CancelFunc

	mu      sync.RWMutex
	wg      sync.WaitGroup
	bundle  []byte
	jwks    *jose.JSONWebKeySet
	modTime time.Time
}

func NewWorkloadAPISource(config WorkloadAPISourceConfig) (*WorkloadAPISource, error) {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultWorkloadAPIPollInterval
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	var opts []workload.DialOption
	if config.SocketPath != "" {
		opts = append(opts, workload.WithAddr("unix://"+config.SocketPath))
	}

	conn, err := workload.Dial(opts...)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &WorkloadAPISource{
		log:           config.Log,
		clock:         config.Clock,
		cancel:        cancel,
		trustDomainID: idutil.TrustDomainID(config.TrustDomain),
	}

	go s.pollEvery(ctx, conn, config.PollInterval)
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

func (s *WorkloadAPISource) pollEvery(ctx context.Context, conn *grpc.ClientConn, interval time.Duration) {
	s.wg.Add(1)
	defer s.wg.Done()

	defer conn.Close()

	client := workload_pb.NewSpiffeWorkloadAPIClient(conn)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))

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

func (s *WorkloadAPISource) pollOnce(ctx context.Context, client workload_pb.SpiffeWorkloadAPIClient) {
	// Ensure the stream gets cleaned up
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.FetchJWTBundles(ctx, &workload_pb.JWTBundlesRequest{})
	if err != nil {
		s.log.WithError(err).Warn("Failed to fetch JWKS from the Workload API")
		return
	}

	resp, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			s.log.Warn("Workload API stream closed before bundle received")
			return
		}
		s.log.WithError(err).Warn("Failed to fetch JWKS from the Workload API")
		return
	}

	s.parseBundle(resp.Bundles[s.trustDomainID])
}

func (s *WorkloadAPISource) parseBundle(bundle []byte) {
	if bundle == nil {
		s.log.WithField("trust_domain_id", s.trustDomainID).Error("No bundle for trust domain in Workload API response")
		return
	}

	// If the bundle hasn't changed, don't bother continuing
	s.mu.RLock()
	if s.bundle != nil && bytes.Equal(s.bundle, bundle) {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	jwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(bundle, jwks); err != nil {
		s.log.WithError(err).Error("Failed to parse trust domain bundle received from the Workload API")
		return
	}

	// Clean the JWKS
	for i, key := range jwks.Keys {
		key.Use = ""
		jwks.Keys[i] = key
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundle = bundle
	s.jwks = jwks
	s.modTime = s.clock.Now()
}
