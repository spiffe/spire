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
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/test/clock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	Clock       clock.Clock
	Log         logrus.FieldLogger
	Manager     manager.Manager
	TrustDomain spiffeid.TrustDomain
	Uptime      func() time.Duration
}

// New creates a new debug service
func New(config Config) *Service {
	return &Service{
		clock:  config.Clock,
		log:    config.Log,
		m:      config.Manager,
		td:     config.TrustDomain,
		uptime: config.Uptime,
	}
}

// Service implements debug server
type Service struct {
	debugv1.UnsafeDebugServer

	clock  clock.Clock
	log    logrus.FieldLogger
	m      manager.Manager
	td     spiffeid.TrustDomain
	uptime func() time.Duration

	getInfoResp getInfoResp
}

type getInfoResp struct {
	mtx  sync.Mutex
	resp *debugv1.GetInfoResponse
	ts   time.Time
}

// GetInfo gets SPIRE Agent debug information
func (s *Service) GetInfo(context.Context, *debugv1.GetInfoRequest) (*debugv1.GetInfoResponse, error) {
	s.getInfoResp.mtx.Lock()
	defer s.getInfoResp.mtx.Unlock()

	// Update cache when expired or does not exists
	if s.getInfoResp.ts.IsZero() || s.clock.Now().Sub(s.getInfoResp.ts) >= cacheExpiry {
		state := s.m.GetCurrentCredentials()
		// Get current agent's credential SVID
		svid := state.SVID
		certChain, err := s.getCertificateChain(svid)
		if err != nil {
			return nil, err
		}

		// Create SVID chain for response
		var svidChain []*debugv1.GetInfoResponse_Cert
		for _, cert := range certChain {
			svidChain = append(svidChain, &debugv1.GetInfoResponse_Cert{
				Id:        spiffeIDFromCert(cert),
				ExpiresAt: cert.NotAfter.Unix(),
				Subject:   cert.Subject.String(),
			})
		}

		// Reset clock and set current response
		s.getInfoResp.ts = s.clock.Now()
		s.getInfoResp.resp = &debugv1.GetInfoResponse{
			SvidChain:       svidChain,
			Uptime:          int32(s.uptime().Seconds()),
			SvidsCount:      int32(s.m.CountSVIDs()),
			LastSyncSuccess: s.m.GetLastSync().UTC().Unix(),
		}
	}

	return s.getInfoResp.resp, nil
}

// spiffeIDFromCert gets types SPIFFE ID from certificate, it can be nil
func spiffeIDFromCert(cert *x509.Certificate) *types.SPIFFEID {
	id, err := x509svid.IDFromCert(cert)
	if err != nil {
		return nil
	}

	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().Name(),
		Path:        id.Path(),
	}
}

func (s *Service) getCertificateChain(svid []*x509.Certificate) ([]*x509.Certificate, error) {
	// Get cached bundle
	cachedBundle := s.m.GetBundle()

	// Create bundle source using SVID roots, and verify certificate to extract SVID chain
	bundleSource := x509bundle.FromX509Authorities(s.td, cachedBundle.X509Authorities())
	_, certs, err := x509svid.Verify(svid, bundleSource)
	if err != nil {
		s.log.WithError(err).Error("Failed to verify agent SVID")
		return nil, status.Errorf(codes.Internal, "failed to verify agent SVID: %v", err)
	}

	return certs[0], nil
}
