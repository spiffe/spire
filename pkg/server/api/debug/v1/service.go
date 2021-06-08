package debug

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/test/clock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	cacheExpiry = 5 * time.Second
)

// RegisterService registers debug service on provided server
func RegisterService(s *grpc.Server, service *Service) {
	debugv1.RegisterDebugServer(s, service)
}

// Config configurations for debug service
type Config struct {
	Clock        clock.Clock
	DataStore    datastore.DataStore
	SVIDObserver svid.Observer
	TrustDomain  spiffeid.TrustDomain
	Uptime       func() time.Duration
}

// New creates a new debug service
func New(config Config) *Service {
	return &Service{
		clock:  config.Clock,
		ds:     config.DataStore,
		so:     config.SVIDObserver,
		td:     config.TrustDomain,
		uptime: config.Uptime,
	}
}

// Service implements debug server
type Service struct {
	debugv1.UnsafeDebugServer

	clock  clock.Clock
	ds     datastore.DataStore
	so     svid.Observer
	td     spiffeid.TrustDomain
	uptime func() time.Duration

	getInfoResp getInfoResp
}

type getInfoResp struct {
	mtx  sync.Mutex
	resp *debugv1.GetInfoResponse
	ts   time.Time
}

// GetInfo gets SPIRE Server debug information
func (s *Service) GetInfo(ctx context.Context, req *debugv1.GetInfoRequest) (*debugv1.GetInfoResponse, error) {
	log := rpccontext.Logger(ctx)

	s.getInfoResp.mtx.Lock()
	defer s.getInfoResp.mtx.Unlock()

	// Update cache when expired or does not exists
	if s.getInfoResp.ts.IsZero() || s.clock.Now().Sub(s.getInfoResp.ts) >= cacheExpiry {
		nodes, err := s.ds.CountAttestedNodes(ctx)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to count agents", err)
		}

		entries, err := s.ds.CountRegistrationEntries(ctx)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to count entries", err)
		}

		bundles, err := s.ds.CountBundles(ctx)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to count bundles", err)
		}

		svidChain, err := s.getCertificateChain(ctx, log)
		if err != nil {
			return nil, err
		}

		// Reset clock and set current response
		s.getInfoResp.ts = s.clock.Now()
		s.getInfoResp.resp = &debugv1.GetInfoResponse{
			AgentsCount:           nodes,
			EntriesCount:          entries,
			FederatedBundlesCount: bundles,
			SvidChain:             svidChain,
			Uptime:                int32(s.uptime().Seconds()),
		}
	}

	return s.getInfoResp.resp, nil
}

func (s *Service) getCertificateChain(ctx context.Context, log logrus.FieldLogger) ([]*debugv1.GetInfoResponse_Cert, error) {
	trustDomainID := s.td.IDString()

	// Extract trustdomains bundle and append federated bundles
	bundle, err := s.ds.FetchBundle(ctx, trustDomainID)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch trust domain bundle", err)
	}

	if bundle == nil {
		return nil, api.MakeErr(log, codes.NotFound, "trust domain bundle not found", nil)
	}

	// Create bundle source using rootCAs
	var rootCAs []*x509.Certificate
	for _, b := range bundle.RootCas {
		cert, err := x509.ParseCertificate(b.DerBytes)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to parse bundle", err)
		}
		rootCAs = append(rootCAs, cert)
	}
	bundleSource := x509bundle.FromX509Authorities(s.td, rootCAs)

	// Verify certificate to extract SVID chain
	_, chains, err := x509svid.Verify(s.so.State().SVID, bundleSource)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed verification against bundle", err)
	}

	// Create SVID chain for response
	var svidChain []*debugv1.GetInfoResponse_Cert
	for _, cert := range chains[0] {
		svidChain = append(svidChain, &debugv1.GetInfoResponse_Cert{
			Id:        spiffeIDFromCert(cert),
			ExpiresAt: cert.NotAfter.Unix(),
			Subject:   cert.Subject.String(),
		})
	}

	return svidChain, nil
}

// spiffeIDFromCert gets types SPIFFE ID from certificate, it can be nil
func spiffeIDFromCert(cert *x509.Certificate) *types.SPIFFEID {
	id, err := x509svid.IDFromCert(cert)
	if err != nil {
		return nil
	}

	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}
}
