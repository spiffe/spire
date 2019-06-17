package workload

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/api/workload"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeworkloadattestor"
	mock_manager "github.com/spiffe/spire/test/mock/agent/manager"
	mock_cache "github.com/spiffe/spire/test/mock/agent/manager/cache"
	mock_telemetry "github.com/spiffe/spire/test/mock/common/telemetry"
	mock_workload "github.com/spiffe/spire/test/mock/proto/api/workload"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	jwtSigningKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGZx/yLVskGyXAyIT
uDe7PI1X4Dt1boMWfysKPyOJeMuhRANCAARzgo1R4J4xtjGpmGFNl2KADaxDpgx3
KfDQqPUcYWUMm2JbwFyHxQfhJfSf+Mla5C4FnJG6Ksa7pWjITPf5KbHi
-----END PRIVATE KEY-----`)
)

func TestHandler(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
}

type HandlerTestSuite struct {
	suite.Suite

	h    *Handler
	ctrl *gomock.Controller

	attestor *fakeworkloadattestor.WorkloadAttestor
	manager  *mock_manager.MockManager
	metrics  *mock_telemetry.MockMetrics
}

func (s *HandlerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	log, _ := test.NewNullLogger()

	s.attestor = fakeworkloadattestor.New()
	s.manager = mock_manager.NewMockManager(mockCtrl)
	s.metrics = mock_telemetry.NewMockMetrics(mockCtrl)

	catalog := fakeagentcatalog.New()
	catalog.SetWorkloadAttestors(fakeagentcatalog.WorkloadAttestor("fake", s.attestor))

	h := &Handler{
		Manager: s.manager,
		Catalog: catalog,
		L:       log,
		M:       s.metrics,
	}

	s.h = h
	s.ctrl = mockCtrl
}

func (s *HandlerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *HandlerTestSuite) TestFetchX509SVID() {
	// Without the security header
	stream := mock_workload.NewMockSpiffeWorkloadAPI_FetchX509SVIDServer(s.ctrl)
	stream.EXPECT().Context().Return(context.Background())
	err := s.h.FetchX509SVID(nil, stream)
	s.Assert().Error(err)

	// Without PID data
	ctx := makeContext(0)
	stream.EXPECT().Context().Return(ctx)
	err = s.h.FetchX509SVID(nil, stream)
	s.Assert().Error(err)

	ctx, cancel := context.WithCancel(makeContext(1))
	defer cancel()

	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	subscriber := mock_cache.NewMockSubscriber(s.ctrl)
	subscription := make(chan *cache.WorkloadUpdate)
	subscriber.EXPECT().Updates().Return(subscription).AnyTimes()
	subscriber.EXPECT().Finish()
	result := make(chan error, 1)
	stream.EXPECT().Context().Return(ctx).AnyTimes()
	s.attestor.SetSelectors(1, selectors)
	s.manager.EXPECT().SubscribeToCacheChanges(cache.Selectors{selectors[0]}).Return(subscriber)
	stream.EXPECT().Send(gomock.Any())

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels)
	labelsSvidResponse := append(labels, []telemetry.Label{
		{Name: telemetry.SVIDType, Value: telemetry.X509},
		{Name: telemetry.Registered, Value: "true"},
		{Name: telemetry.SPIFFEID, Value: "spiffe://example.org/foo"},
	}...)
	s.metrics.EXPECT().SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.TTL},
		gomock.Any(),
		append(labels, telemetry.Label{
			Name: telemetry.SPIFFEID, Value: "spiffe://example.org/foo",
		}))
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID}, float32(1), labelsSvidResponse)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.ElapsedTime}, gomock.Any(), labelsSvidResponse)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.SVIDResponseLatency, telemetry.Fetch}, gomock.Any(), labels)

	go func() { result <- s.h.FetchX509SVID(nil, stream) }()

	// Make sure it's still running...
	select {
	case err := <-result:
		s.T().Errorf("hander exited immediately: %v", err)
	case <-time.NewTimer(1 * time.Millisecond).C:
	}

	select {
	case <-time.NewTimer(1 * time.Second).C:
		s.T().Error("timeout sending update to workload handler")
	case subscription <- s.workloadUpdate():
	}

	cancel()
	select {
	case err := <-result:
		s.Assert().NoError(err)
	case <-time.NewTimer(1 * time.Second).C:
		s.T().Error("workload handler hung, shutdown timer exceeded")
	}
}

func (s *HandlerTestSuite) TestSendX509Response() {
	stream := mock_workload.NewMockSpiffeWorkloadAPI_FetchX509SVIDServer(s.ctrl)
	emptyUpdate := new(cache.WorkloadUpdate)
	stream.EXPECT().Send(gomock.Any()).Times(0)

	labels := []telemetry.Label{
		{Name: telemetry.SVIDType, Value: telemetry.X509},
		{Name: telemetry.Registered, Value: "false"},
	}
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.Error}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.Error, telemetry.ElapsedTime}, gomock.Any(), labels)

	err := s.h.sendX509SVIDResponse(emptyUpdate, stream, s.h.M, []*common.Selector{})
	s.Assert().Error(err)

	resp, err := s.h.composeX509SVIDResponse(s.workloadUpdate())
	s.Require().NoError(err)
	stream.EXPECT().Send(resp)

	labels = []telemetry.Label{
		{Name: telemetry.SVIDType, Value: telemetry.X509},
		{Name: telemetry.Registered, Value: "true"},
		{Name: telemetry.SPIFFEID, Value: "spiffe://example.org/foo"},
	}
	s.metrics.EXPECT().SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.TTL},
		gomock.Any(),
		[]telemetry.Label{
			{Name: telemetry.SPIFFEID, Value: "spiffe://example.org/foo"},
		})
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.ElapsedTime}, gomock.Any(), labels)

	err = s.h.sendX509SVIDResponse(s.workloadUpdate(), stream, s.h.M, []*common.Selector{})
	s.Assert().NoError(err)
}

func (s *HandlerTestSuite) TestComposeX509Response() {
	update := s.workloadUpdate()
	keyData, err := x509.MarshalPKCS8PrivateKey(update.Identities[0].PrivateKey)
	s.Require().NoError(err)

	svidMsg := &workload.X509SVID{
		SpiffeId:      "spiffe://example.org/foo",
		X509Svid:      update.Identities[0].SVID[0].Raw,
		X509SvidKey:   keyData,
		Bundle:        update.Bundle.RootCAs()[0].Raw,
		FederatesWith: []string{"spiffe://otherdomain.test"},
	}
	apiMsg := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{svidMsg},
		FederatedBundles: map[string][]byte{
			"spiffe://otherdomain.test": update.Bundle.RootCAs()[0].Raw,
		},
	}

	resp, err := s.h.composeX509SVIDResponse(s.workloadUpdate())
	s.Assert().NoError(err)
	s.Assert().Equal(apiMsg, resp)
}

func (s *HandlerTestSuite) TestFetchJWTSVID() {
	audience := []string{"foo"}

	// request missing audience
	resp, err := s.h.FetchJWTSVID(context.Background(), &workload.JWTSVIDRequest{})
	s.requireErrorContains(err, "audience must be specified")
	s.Require().Nil(resp)

	// missing security header
	resp, err = s.h.FetchJWTSVID(context.Background(), &workload.JWTSVIDRequest{
		Audience: audience,
	})
	s.requireErrorContains(err, "Security header missing from request")
	s.Require().Nil(resp)

	// missing peer info
	resp, err = s.h.FetchJWTSVID(makeContext(0), &workload.JWTSVIDRequest{
		Audience: audience,
	})
	s.requireErrorContains(err, "Unable to fetch watcher from context")
	s.Require().Nil(resp)

	// no identity issued
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	s.attestor.SetSelectors(1, selectors)
	s.manager.EXPECT().MatchingIdentities(selectors).Return(nil)

	selectorsLabels := selectorsToLabels(selectors)
	labels := append(selectorsLabels, []telemetry.Label{
		{Name: telemetry.SVIDType, Value: telemetry.JWT},
		{Name: telemetry.Registered, Value: "false"},
	}...)
	setupMetricsCommonExpectations(s.metrics, selectorsLabels)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.Error}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.Error, telemetry.ElapsedTime}, gomock.Any(), labels)

	resp, err = s.h.FetchJWTSVID(makeContext(1), &workload.JWTSVIDRequest{
		Audience: audience,
	})
	s.requireErrorContains(err, "no identity issued")
	s.Require().Nil(resp)

	// fetch SVIDs for all SPIFFE IDs
	identities := []cache.Identity{
		{
			Entry: &common.RegistrationEntry{
				SpiffeId: "spiffe://example.org/one",
			},
		},
		{
			Entry: &common.RegistrationEntry{
				SpiffeId: "spiffe://example.org/two",
			},
		},
	}
	s.attestor.SetSelectors(1, selectors)
	s.manager.EXPECT().MatchingIdentities(selectors).Return(identities)
	ONE := &client.JWTSVID{Token: "ONE"}
	TWO := &client.JWTSVID{Token: "TWO"}
	s.manager.EXPECT().FetchJWTSVID(gomock.Any(), "spiffe://example.org/one", audience).Return(ONE, nil)
	s.manager.EXPECT().FetchJWTSVID(gomock.Any(), "spiffe://example.org/two", audience).Return(TWO, nil)

	setupMetricsCommonExpectations(s.metrics, selectorsLabels)
	labels = append(selectorsLabels, []telemetry.Label{
		{Name: telemetry.SVIDType, Value: telemetry.JWT},
		{Name: telemetry.Registered, Value: "true"},
		{Name: telemetry.SPIFFEID, Value: "spiffe://example.org/one"},
		{Name: telemetry.SPIFFEID, Value: "spiffe://example.org/two"},
	}...)

	s.metrics.EXPECT().SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.TTL},
		gomock.Any(),
		append(selectorsLabels, telemetry.Label{
			Name: telemetry.SPIFFEID, Value: "spiffe://example.org/one",
		}))
	s.metrics.EXPECT().SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.TTL},
		gomock.Any(),
		append(selectorsLabels, telemetry.Label{
			Name: telemetry.SPIFFEID, Value: "spiffe://example.org/two",
		}))
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.ElapsedTime}, gomock.Any(), labels)

	resp, err = s.h.FetchJWTSVID(makeContext(1), &workload.JWTSVIDRequest{
		Audience: audience,
	})
	s.Require().NoError(err)
	s.Require().Equal(&workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{
			{
				SpiffeId: "spiffe://example.org/one",
				Svid:     "ONE",
			},
			{
				SpiffeId: "spiffe://example.org/two",
				Svid:     "TWO",
			},
		},
	}, resp)

	// fetch SVIDs for specific SPIFFE ID
	s.attestor.SetSelectors(1, selectors)
	s.manager.EXPECT().MatchingIdentities(selectors).Return(identities)
	s.manager.EXPECT().FetchJWTSVID(gomock.Any(), "spiffe://example.org/two", audience).Return(TWO, nil)

	selectorsLabels = selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, selectorsLabels)
	labels = append(selectorsLabels, []telemetry.Label{
		{Name: telemetry.SVIDType, Value: telemetry.JWT},
		{Name: telemetry.Registered, Value: "true"},
		{Name: telemetry.SPIFFEID, Value: "spiffe://example.org/two"},
	}...)
	s.metrics.EXPECT().SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.TTL},
		gomock.Any(),
		append(selectorsLabels, telemetry.Label{
			Name: telemetry.SPIFFEID, Value: "spiffe://example.org/two",
		}))
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.ElapsedTime}, gomock.Any(), labels)

	resp, err = s.h.FetchJWTSVID(makeContext(1), &workload.JWTSVIDRequest{
		SpiffeId: "spiffe://example.org/two",
		Audience: audience,
	})
	s.Require().NoError(err)
	s.Require().Equal(&workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{
			{
				SpiffeId: "spiffe://example.org/two",
				Svid:     "TWO",
			},
		},
	}, resp)
}

func setupMetricsCommonExpectations(metrics *mock_telemetry.MockMetrics, selectorsLabels []telemetry.Label) {
	attestorLabels := []telemetry.Label{{telemetry.Attestor, "fake"}}

	metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency}, float32(1), attestorLabels)
	metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.ElapsedTime}, gomock.Any(), attestorLabels)
	metrics.EXPECT().AddSample([]string{telemetry.WorkloadAPI, telemetry.DiscoveredSelectors}, float32(len(selectorsLabels)))
	metrics.EXPECT().MeasureSince([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestationDuration}, gomock.Any())

	metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.Connection}, float32(1), selectorsLabels)
	metrics.EXPECT().IncrCounter([]string{telemetry.WorkloadAPI, telemetry.Connections}, float32(1))
	metrics.EXPECT().IncrCounter([]string{telemetry.WorkloadAPI, telemetry.Connections}, float32(-1))
}

func (s *HandlerTestSuite) TestFetchJWTBundles() {
	stream := mock_workload.NewMockSpiffeWorkloadAPI_FetchJWTBundlesServer(s.ctrl)

	// missing security header
	stream.EXPECT().Context().Return(context.Background())
	err := s.h.FetchJWTBundles(&workload.JWTBundlesRequest{}, stream)
	s.requireErrorContains(err, "Security header missing from request")

	// missing peer info
	stream.EXPECT().Context().Return(makeContext(0))
	err = s.h.FetchJWTBundles(&workload.JWTBundlesRequest{}, stream)
	s.requireErrorContains(err, "Unable to fetch watcher from context")

	// success
	ctx, cancel := context.WithCancel(makeContext(1))
	defer cancel()
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	subscriber := mock_cache.NewMockSubscriber(s.ctrl)
	subscription := make(chan *cache.WorkloadUpdate)
	subscriber.EXPECT().Updates().Return(subscription).AnyTimes()
	subscriber.EXPECT().Finish()
	result := make(chan error, 1)
	stream.EXPECT().Context().Return(ctx).AnyTimes()
	s.attestor.SetSelectors(1, selectors)
	s.manager.EXPECT().SubscribeToCacheChanges(cache.Selectors{selectors[0]}).Return(subscriber)
	stream.EXPECT().Send(&workload.JWTBundlesResponse{
		Bundles: map[string][]byte{
			"spiffe://example.org":      []byte(`{"keys":null}`),
			"spiffe://otherdomain.test": []byte(`{"keys":null}`),
		},
	})

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.FetchJWTBundles}, float32(1), labels)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.BundlesUpdate, telemetry.JWT}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.SendJWTBundleLatency}, gomock.Any(), labels)

	go func() { result <- s.h.FetchJWTBundles(&workload.JWTBundlesRequest{}, stream) }()

	// Make sure it's still running...
	select {
	case err := <-result:
		s.T().Errorf("hander exited immediately: %v", err)
	case <-time.NewTimer(1 * time.Millisecond).C:
	}

	select {
	case <-time.NewTimer(1 * time.Second).C:
		s.T().Error("timeout sending update to workload handler")
	case subscription <- s.workloadUpdate():
	}

	cancel()
	select {
	case err := <-result:
		s.Assert().NoError(err)
	case <-time.NewTimer(1 * time.Second).C:
		s.T().Error("workload handler hung, shutdown timer exceeded")
	}
}

func (s *HandlerTestSuite) TestComposeJWTBundlesResponse() {
	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	s.Require().NoError(err)

	// no bundles in update
	resp, err := s.h.composeJWTBundlesResponse(&cache.WorkloadUpdate{})
	s.Require().NoError(err)
	s.Require().Empty(resp.Bundles)

	// bundles in update
	hasKeysBundle, err := bundleutil.BundleFromProto(&common.Bundle{
		TrustDomainId: "spiffe://has-keys.test",
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "kid",
				PkixBytes: pkixBytes,
			},
		},
	})
	s.Require().NoError(err)
	noKeysBundle, err := bundleutil.BundleFromProto(&common.Bundle{
		TrustDomainId: "spiffe://no-keys.test",
	})
	s.Require().NoError(err)
	resp, err = s.h.composeJWTBundlesResponse(&cache.WorkloadUpdate{
		Bundle: hasKeysBundle,
		FederatedBundles: map[string]*bundleutil.Bundle{
			"spiffe://no-keys.test": noKeysBundle,
		},
	})
	s.Require().NoError(err)
	s.Require().Len(resp.Bundles, 2)
	s.JSONEq(`{
		"keys": [
			{
				"kid":"kid",
				"use":"spiffe-jwt",
				"kty":"EC",
				"crv":"P-256",
				"x":"YSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw-5WKJwngEL0",
				"y":"6z3PYuE4M8_a4kdyPzYkpZIETtVrMQbrKqQtvOI_XVw"
			}
		]
	}`, string(resp.Bundles["spiffe://has-keys.test"]))
	s.JSONEq(`{
		"keys": null
	}`, string(resp.Bundles["spiffe://no-keys.test"]))
}

func (s *HandlerTestSuite) TestValidateJWTSVID() {
	// no audience
	resp, err := s.h.ValidateJWTSVID(makeContext(0), &workload.ValidateJWTSVIDRequest{})
	s.requireErrorContains(err, "audience must be specified")
	s.Require().Nil(resp)

	// no svid
	resp, err = s.h.ValidateJWTSVID(makeContext(0), &workload.ValidateJWTSVIDRequest{
		Audience: "audience",
	})
	s.requireErrorContains(err, "svid must be specified")
	s.Require().Nil(resp)

	// missing security header
	resp, err = s.h.ValidateJWTSVID(context.Background(), &workload.ValidateJWTSVIDRequest{
		Audience: "audience",
		Svid:     "svid",
	})
	s.requireErrorContains(err, "Security header missing from request")
	s.Require().Nil(resp)

	// missing peer info
	resp, err = s.h.ValidateJWTSVID(makeContext(0), &workload.ValidateJWTSVIDRequest{
		Audience: "audience",
		Svid:     "svid",
	})
	s.requireErrorContains(err, "Unable to fetch watcher from context")
	s.Require().Nil(resp)

	// set up attestation
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	s.attestor.SetSelectors(1, selectors)

	// token validation failed
	s.manager.EXPECT().FetchWorkloadUpdate(selectors).Return(&cache.WorkloadUpdate{})

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels)
	labels = append(labels, []telemetry.Label{
		{Name: telemetry.Error, Value: "token contains an invalid number of segments"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.ValidateJWTSVID}, float32(1), labels)

	resp, err = s.h.ValidateJWTSVID(makeContext(1), &workload.ValidateJWTSVIDRequest{
		Audience: "audience",
		Svid:     "svid",
	})
	s.Require().Equal(codes.InvalidArgument, status.Convert(err).Code())
	s.requireErrorContains(err, "token contains an invalid number of segments")
	s.Require().Nil(resp)

	// build up bundle and sign token with key
	key, err := pemutil.ParsePrivateKey(jwtSigningKeyPEM)
	s.Require().NoError(err)
	signer, ok := key.(crypto.Signer)
	s.Require().True(ok)
	pkixBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	s.Require().NoError(err)

	bundle, err := bundleutil.BundleFromProto(&common.Bundle{
		TrustDomainId: "spiffe://example.org",
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "kid",
				PkixBytes: pkixBytes,
			},
		},
	})
	s.Require().NoError(err)

	jwtSigner := jwtsvid.NewSigner(jwtsvid.SignerConfig{})

	svid, err := jwtSigner.SignToken(
		"spiffe://example.org/blog",
		[]string{"audience"},
		time.Now().Add(time.Minute),
		signer,
		"kid",
	)
	s.Require().NoError(err)

	labels = selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels)
	labels = append(labels, []telemetry.Label{
		{Name: telemetry.Subject, Value: "spiffe://example.org/blog"},
		{Name: telemetry.Audience, Value: "audience"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.ValidateJWTSVID}, float32(1), labels)

	// token validated by bundle
	s.manager.EXPECT().FetchWorkloadUpdate(selectors).Return(&cache.WorkloadUpdate{
		Bundle: bundle,
	})
	resp, err = s.h.ValidateJWTSVID(makeContext(1), &workload.ValidateJWTSVIDRequest{
		Audience: "audience",
		Svid:     svid,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal("spiffe://example.org/blog", resp.SpiffeId)
	s.Require().NotNil(resp.Claims)
	s.Require().Len(resp.Claims.Fields, 4)

	// token validated by federated bundle
	s.manager.EXPECT().FetchWorkloadUpdate(selectors).Return(&cache.WorkloadUpdate{
		FederatedBundles: map[string]*bundleutil.Bundle{
			"spiffe://example.org": bundle,
		},
	})

	labels = selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels)
	labels = append(labels, []telemetry.Label{
		{Name: telemetry.Subject, Value: "spiffe://example.org/blog"},
		{Name: telemetry.Audience, Value: "audience"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.ValidateJWTSVID}, float32(1), labels)

	resp, err = s.h.ValidateJWTSVID(makeContext(1), &workload.ValidateJWTSVIDRequest{
		Audience: "audience",
		Svid:     svid,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Equal("spiffe://example.org/blog", resp.SpiffeId)
	s.Require().NotNil(resp.Claims)
	s.Require().Len(resp.Claims.Fields, 4)
}

func (s *HandlerTestSuite) TestStructFromValues() {
	expected := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"foo": {
				Kind: &structpb.Value_StringValue{
					StringValue: "bar",
				},
			},
			"baz": {
				Kind: &structpb.Value_NumberValue{
					NumberValue: 3.0,
				},
			},
		},
	}

	actual, err := structFromValues(map[string]interface{}{
		"foo": "bar",
		"baz": 3,
	})
	s.Require().NoError(err)
	s.Require().Equal(expected, actual)
}

func (s *HandlerTestSuite) TestPeerWatcher() {
	p := &peer.Peer{
		AuthInfo: peertracker.AuthInfo{
			Watcher: FakeWatcher{},
		},
	}
	ctx := peer.NewContext(context.Background(), p)

	watcher, err := s.h.peerWatcher(ctx)
	s.Assert().NoError(err)
	s.Assert().Equal(int32(1), watcher.PID())

	// Implementation error - custom auth creds not in use
	p.AuthInfo = nil
	ctx = peer.NewContext(context.Background(), p)
	_, err = s.h.peerWatcher(ctx)
	s.Assert().Error(err)
}

func (s *HandlerTestSuite) workloadUpdate() *cache.WorkloadUpdate {
	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	ca, _, err := util.LoadCAFixture()
	s.Require().NoError(err)

	identity := cache.Identity{
		SVID:       []*x509.Certificate{svid},
		PrivateKey: key,
		Entry: &common.RegistrationEntry{
			SpiffeId:      "spiffe://example.org/foo",
			FederatesWith: []string{"spiffe://otherdomain.test"},
		},
	}

	update := &cache.WorkloadUpdate{
		Identities: []cache.Identity{identity},
		Bundle:     bundleutil.BundleFromRootCA("spiffe://example.org", ca),
		FederatedBundles: map[string]*bundleutil.Bundle{
			"spiffe://otherdomain.test": bundleutil.BundleFromRootCA("spiffe://otherdomain.test", ca),
		},
	}

	return update
}

func (s *HandlerTestSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}

func makeContext(pid int) context.Context {
	header := metadata.Pairs("workload.spiffe.io", "true")
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, header)

	if pid > 0 {
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: peertracker.AuthInfo{
				Watcher: FakeWatcher{},
			},
		})
	}

	return ctx
}

type FakeWatcher struct{}

func (w FakeWatcher) Close() {}

func (w FakeWatcher) IsAlive() error { return nil }

func (w FakeWatcher) PID() int32 { return 1 }
