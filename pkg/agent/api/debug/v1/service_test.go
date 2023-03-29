package debug_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	debug "github.com/spiffe/spire/pkg/agent/api/debug/v1"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx = context.Background()
	td  = spiffeid.RequireTrustDomainFromString("example.org")
)

func TestGetInfo(t *testing.T) {
	now := time.Now()
	// Create root CA
	ca := testca.New(t, td)
	cachedBundleCert := ca.Bundle().X509Authorities()[0]
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	cachedBundle := spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{cachedBundleCert})

	x509SVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/spire/agent/foo"))

	x509SVIDState := svid.State{
		SVID: x509SVID.Certificates,
		Key:  x509SVID.PrivateKey.(*ecdsa.PrivateKey),
	}
	x509SVIDChain := []*debugv1.GetInfoResponse_Cert{
		{
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/foo"},
			ExpiresAt: x509SVID.Certificates[0].NotAfter.Unix(),
			Subject:   x509SVID.Certificates[0].Subject.String(),
		},
		{
			ExpiresAt: cachedBundleCert.NotAfter.Unix(),
			Subject:   cachedBundleCert.Subject.String(),
		},
	}

	// Create intermediate with SPIFFE ID and subject
	intermediateCANoAfter := now.Add(2 * time.Minute)
	intermediateCA := ca.ChildCA(testca.WithID(td.ID()),
		testca.WithLifetime(now, intermediateCANoAfter),
		testca.WithSubject(pkix.Name{CommonName: "UPSTREAM-1"}))

	// Create SVID with intermediate
	svidWithIntermediate := intermediateCA.CreateX509SVID(spiffeid.RequireFromPath(td, "/spire/agent/bar"))
	stateWithIntermediate := svid.State{
		SVID: svidWithIntermediate.Certificates,
		Key:  svidWithIntermediate.PrivateKey.(*ecdsa.PrivateKey),
	}
	// Manually create SVID chain with intemediate
	svidWithIntermediateChain := []*debugv1.GetInfoResponse_Cert{
		{
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/bar"},
			ExpiresAt: svidWithIntermediate.Certificates[0].NotAfter.Unix(),
			Subject:   svidWithIntermediate.Certificates[0].Subject.String(),
		},
		{
			Id:        &types.SPIFFEID{TrustDomain: "example.org"},
			ExpiresAt: intermediateCANoAfter.Unix(),
			Subject:   "CN=UPSTREAM-1",
		},
		{
			ExpiresAt: cachedBundleCert.NotAfter.Unix(),
			Subject:   cachedBundleCert.Subject.String(),
		},
	}
	clk := clock.NewMock(t)
	lastSync := clk.Now()
	cachedLastSync := clk.Now().Add(time.Minute)

	for _, tt := range []struct {
		name string

		code         codes.Code
		err          string
		expectResp   *debugv1.GetInfoResponse
		expectedLogs []spiretest.LogEntry
		// Time to add to clock.Mock
		addToClk  time.Duration
		initCache bool
		lastSync  time.Time
		svidCount int
		svidState svid.State
	}{
		{
			name:      "svid without intermediate",
			lastSync:  lastSync,
			svidState: x509SVIDState,
			svidCount: 123,
			expectResp: &debugv1.GetInfoResponse{
				LastSyncSuccess: lastSync.UTC().Unix(),
				SvidsCount:      123,
				SvidChain:       x509SVIDChain,
			},
		},
		{
			name:      "svid with intermediate",
			lastSync:  lastSync,
			svidState: stateWithIntermediate,
			svidCount: 456,
			expectResp: &debugv1.GetInfoResponse{
				LastSyncSuccess: lastSync.UTC().Unix(),
				SvidsCount:      456,
				SvidChain:       svidWithIntermediateChain,
			},
		},
		{
			name: "get response from cache",
			expectResp: &debugv1.GetInfoResponse{
				LastSyncSuccess: cachedLastSync.Unix(),
				SvidsCount:      99999,
				SvidChain:       x509SVIDChain,
			},
			initCache: true,
			lastSync:  lastSync,
			svidState: stateWithIntermediate,
			svidCount: 456,
		},
		{
			name:      "expires cache",
			svidState: stateWithIntermediate,
			initCache: true,
			addToClk:  5 * time.Second,
			lastSync:  lastSync,
			expectResp: &debugv1.GetInfoResponse{
				LastSyncSuccess: lastSync.UTC().Unix(),
				SvidChain:       svidWithIntermediateChain,
				// Seconds added to clk
				Uptime: 5,
			},
		},
		{
			name: "fails to verify chain",
			svidState: svid.State{
				// Change order to make verify fails
				SVID: append(ca.X509Authorities(), x509SVID.Certificates...),
			},
			svidCount: 123,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to verify agent SVID",
					Data: logrus.Fields{
						logrus.ErrorKey: "x509svid: could not get leaf SPIFFE ID: certificate contains no URI SAN",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to verify agent SVID: x509svid: could not get leaf SPIFFE ID: certificate contains no URI SAN",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			test.m.bundle = cachedBundle

			// Set a success state before running actual test case and expire time
			if tt.initCache {
				test.m.svidCount = 99999
				test.m.svidState = x509SVIDState
				test.m.lastSync = cachedLastSync

				_, err := test.client.GetInfo(ctx, &debugv1.GetInfoRequest{})
				require.NoError(t, err)
			}
			// Cache expires after 5s
			test.clk.Add(tt.addToClk)

			test.m.svidCount = tt.svidCount
			test.m.svidState = tt.svidState
			test.m.lastSync = tt.lastSync

			resp, err := test.client.GetInfo(ctx, &debugv1.GetInfoRequest{})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)
			if tt.err != "" {
				spiretest.AssertGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}
			require.NoError(t, err)

			// Set uptime from endpoint
			spiretest.RequireProtoEqual(t, tt.expectResp, resp)
		})
	}
}

type serviceTest struct {
	client debugv1.DebugClient
	done   func()

	clk     *clock.Mock
	logHook *test.Hook
	m       *fakeManager
	uptime  *fakeUptime
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	clk := clock.NewMock(t)
	manager := &fakeManager{}
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	fakeUptime := &fakeUptime{
		start: clk.Now(),
		clk:   clk,
	}

	service := debug.New(debug.Config{
		Clock:       clk,
		Log:         log,
		Manager:     manager,
		TrustDomain: td,
		Uptime:      fakeUptime.uptime,
	})

	test := &serviceTest{
		clk:     clk,
		logHook: logHook,
		m:       manager,
		uptime:  fakeUptime,
	}

	registerFn := func(s *grpc.Server) {
		debug.RegisterService(s, service)
	}
	contextFn := func(ctx context.Context) context.Context {
		return ctx
	}
	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = debugv1.NewDebugClient(conn)

	return test
}

type fakeManager struct {
	manager.Manager

	bundle    *cache.Bundle
	svidState svid.State
	svidCount int
	lastSync  time.Time
}

func (m *fakeManager) GetCurrentCredentials() svid.State {
	return m.svidState
}

func (m *fakeManager) CountSVIDs() int {
	return m.svidCount
}

func (m *fakeManager) GetLastSync() time.Time {
	return m.lastSync
}

func (m *fakeManager) GetBundle() *cache.Bundle {
	return m.bundle
}

type fakeUptime struct {
	start time.Time
	clk   *clock.Mock
}

func (f *fakeUptime) uptime() time.Duration {
	return f.clk.Now().Sub(f.start)
}
