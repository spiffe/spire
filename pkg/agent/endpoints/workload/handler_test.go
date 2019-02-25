package workload

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	mock_manager "github.com/spiffe/spire/test/mock/agent/manager"
	mock_cache "github.com/spiffe/spire/test/mock/agent/manager/cache"
	mock_telemetry "github.com/spiffe/spire/test/mock/common/telemetry"
	mock_workloadattestor "github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
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

type HandlerTestSuite struct {
	suite.Suite

	h    *Handler
	ctrl *gomock.Controller

	attestor *mock_workloadattestor.MockWorkloadAttestor
	cache    *mock_cache.MockCache
	manager  *mock_manager.MockManager
	metrics  *mock_telemetry.MockMetrics
}

func (s *HandlerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	log, _ := test.NewNullLogger()

	s.attestor = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.cache = mock_cache.NewMockCache(mockCtrl)
	s.manager = mock_manager.NewMockManager(mockCtrl)
	s.metrics = mock_telemetry.NewMockMetrics(mockCtrl)

	catalog := fakeagentcatalog.New()
	catalog.SetWorkloadAttestors(s.attestor)

	h := &Handler{
		Manager: s.manager,
		Catalog: catalog,
		L:       log,
		M:       s.metrics,
	}

	s.h = h
	s.ctrl = mockCtrl
}

func TestWorkloadServer(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
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
	s.attestor.EXPECT().Attest(gomock.Any(), &workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{Selectors: selectors}, nil)
	s.manager.EXPECT().SubscribeToCacheChanges(cache.Selectors{selectors[0]}).Return(subscriber)
	stream.EXPECT().Send(gomock.Any())

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	labelsSvidResponse := append(labels, []telemetry.Label{
		{Name: "svid_type", Value: "x509"},
		{Name: "registered", Value: "true"},
		{Name: "spiffe_id", Value: "spiffe://example.org/foo"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "fetch_x509_svid"}, float32(1), labelsSvidResponse)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{workloadApi, "svid_response_latency"}, gomock.Any(), labels)

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
		{Name: "svid_type", Value: "x509"},
		{Name: "registered", Value: "false"},
	}
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "fetch_x509_svid"}, float32(1), labels)

	err := s.h.sendX509SVIDResponse(emptyUpdate, stream, s.h.M, []*common.Selector{})
	s.Assert().Error(err)

	resp, err := s.h.composeX509SVIDResponse(s.workloadUpdate())
	s.Require().NoError(err)
	stream.EXPECT().Send(resp)

	labels = []telemetry.Label{
		{Name: "svid_type", Value: "x509"},
		{Name: "registered", Value: "true"},
		{Name: "spiffe_id", Value: "spiffe://example.org/foo"},
	}
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "fetch_x509_svid"}, float32(1), labels)

	err = s.h.sendX509SVIDResponse(s.workloadUpdate(), stream, s.h.M, []*common.Selector{})
	s.Assert().NoError(err)
}

func (s *HandlerTestSuite) TestComposeX509Response() {
	update := s.workloadUpdate()
	keyData, err := x509.MarshalPKCS8PrivateKey(update.Entries[0].PrivateKey)
	s.Require().NoError(err)

	svidMsg := &workload.X509SVID{
		SpiffeId:      "spiffe://example.org/foo",
		X509Svid:      update.Entries[0].SVID[0].Raw,
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
	s.requireErrorContains(err, "Unable to fetch credentials from context")
	s.Require().Nil(resp)

	// fetch SVIDs for all SPIFFE IDs
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	entries := []*cache.Entry{
		{
			RegistrationEntry: &common.RegistrationEntry{
				SpiffeId: "spiffe://example.org/one",
			},
		},
		{
			RegistrationEntry: &common.RegistrationEntry{
				SpiffeId: "spiffe://example.org/two",
			},
		},
	}
	s.attestor.EXPECT().Attest(gomock.Any(), &workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{Selectors: selectors}, nil)
	s.manager.EXPECT().MatchingEntries(selectors).Return(entries)
	s.manager.EXPECT().FetchJWTSVID(gomock.Any(), "spiffe://example.org/one", audience).Return("ONE", nil)
	s.manager.EXPECT().FetchJWTSVID(gomock.Any(), "spiffe://example.org/two", audience).Return("TWO", nil)

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	labels = append(labels, []telemetry.Label{
		{Name: "svid_type", Value: "jwt"},
		{Name: "registered", Value: "true"},
		{Name: "spiffe_id", Value: "spiffe://example.org/one"},
		{Name: "spiffe_id", Value: "spiffe://example.org/two"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "fetch_jwt_svid"}, float32(1), labels)

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
	s.attestor.EXPECT().Attest(gomock.Any(), &workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{Selectors: selectors}, nil)
	s.manager.EXPECT().MatchingEntries(selectors).Return(entries)
	s.manager.EXPECT().FetchJWTSVID(gomock.Any(), "spiffe://example.org/two", audience).Return("TWO", nil)

	labels = selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	labels = append(labels, []telemetry.Label{
		{Name: "svid_type", Value: "jwt"},
		{Name: "registered", Value: "true"},
		{Name: "spiffe_id", Value: "spiffe://example.org/two"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "fetch_jwt_svid"}, float32(1), labels)

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

func setupMetricsCommonExpectations(metrics *mock_telemetry.MockMetrics, selectorsLabels []telemetry.Label, pid int32) {
	attestorLabels := []telemetry.Label{{"attestor_name", "fake_workloadattestor_1"}}

	metrics.EXPECT().MeasureSinceWithLabels([]string{workloadApi, "workload_attestor_latency"}, gomock.Any(), attestorLabels)
	metrics.EXPECT().AddSample([]string{workloadApi, "discovered_selectors"}, float32(len(selectorsLabels)))
	metrics.EXPECT().MeasureSince([]string{workloadApi, "workload_attestation_duration"}, gomock.Any())

	metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "connection"}, float32(1), selectorsLabels)
	metrics.EXPECT().IncrCounter([]string{workloadApi, "connections"}, float32(1))
	metrics.EXPECT().IncrCounter([]string{workloadApi, "connections"}, float32(-1))
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
	s.requireErrorContains(err, "Unable to fetch credentials from context")

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
	s.attestor.EXPECT().Attest(gomock.Any(), &workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{Selectors: selectors}, nil)
	s.manager.EXPECT().SubscribeToCacheChanges(cache.Selectors{selectors[0]}).Return(subscriber)
	stream.EXPECT().Send(&workload.JWTBundlesResponse{
		Bundles: map[string][]byte{
			"spiffe://example.org":      []byte(`{"keys":null}`),
			"spiffe://otherdomain.test": []byte(`{"keys":null}`),
		},
	})

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "fetch_jwt_bundles"}, float32(1), labels)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "bundles_update"}, float32(1), labels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{workloadApi, "send_jwt_bundle_latency"}, gomock.Any(), labels)

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
	s.requireErrorContains(err, "Unable to fetch credentials from context")
	s.Require().Nil(resp)

	// set up attestation
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	s.attestor.EXPECT().Attest(gomock.Any(), &workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{Selectors: selectors}, nil).AnyTimes()

	// token validation failed
	s.manager.EXPECT().FetchWorkloadUpdate(selectors).Return(&cache.WorkloadUpdate{})

	labels := selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	labels = append(labels, []telemetry.Label{
		{Name: "error", Value: "token contains an invalid number of segments"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "validate_jwt_svid"}, float32(1), labels)

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

	svid, err := jwtsvid.SignToken(
		"spiffe://example.org/blog",
		[]string{"audience"},
		time.Now().Add(time.Minute),
		signer,
		"kid",
	)
	s.Require().NoError(err)

	labels = selectorsToLabels(selectors)
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	labels = append(labels, []telemetry.Label{
		{Name: "subject", Value: "spiffe://example.org/blog"},
		{Name: "audience", Value: "audience"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "validate_jwt_svid"}, float32(1), labels)

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
	setupMetricsCommonExpectations(s.metrics, labels, 1)
	labels = append(labels, []telemetry.Label{
		{Name: "subject", Value: "spiffe://example.org/blog"},
		{Name: "audience", Value: "audience"},
	}...)
	s.metrics.EXPECT().IncrCounterWithLabels([]string{workloadApi, "validate_jwt_svid"}, float32(1), labels)

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

func (s *HandlerTestSuite) TestCallerPID() {
	p := &peer.Peer{
		AuthInfo: auth.CallerInfo{
			PID: 1,
		},
	}
	ctx := peer.NewContext(context.Background(), p)

	pid, err := s.h.callerPID(ctx)
	s.Assert().NoError(err)
	s.Assert().Equal(int32(1), pid)

	// Couldn't get PID via socket opt
	p = &peer.Peer{
		AuthInfo: auth.CallerInfo{
			PID: 0,
			Err: errors.New("i'm an error"),
		},
	}
	ctx = peer.NewContext(context.Background(), p)
	_, err = s.h.callerPID(ctx)
	s.Assert().Error(err)

	// Implementation error - custom auth creds not in use
	p.AuthInfo = nil
	ctx = peer.NewContext(context.Background(), p)
	_, err = s.h.callerPID(ctx)
	s.Assert().Error(err)
}

func (s *HandlerTestSuite) workloadUpdate() *cache.WorkloadUpdate {
	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	ca, _, err := util.LoadCAFixture()
	s.Require().NoError(err)

	entry := cache.Entry{
		SVID:       []*x509.Certificate{svid},
		PrivateKey: key,
		RegistrationEntry: &common.RegistrationEntry{
			SpiffeId:      "spiffe://example.org/foo",
			FederatesWith: []string{"spiffe://otherdomain.test"},
		},
	}

	update := &cache.WorkloadUpdate{
		Entries: []*cache.Entry{&entry},
		Bundle:  bundleutil.BundleFromRootCA("spiffe://example.org", ca),
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
			AuthInfo: auth.CallerInfo{
				PID: 1,
			},
		})
	}

	return ctx
}
