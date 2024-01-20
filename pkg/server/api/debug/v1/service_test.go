package debug_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	debug "github.com/spiffe/spire/pkg/server/api/debug/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/svid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	federatedBundle = `-----BEGIN CERTIFICATE-----
MIIBmjCCAUCgAwIBAgIJAJQ2zT1xCwf9MAkGByqGSM49BAEwNTELMAkGA1UEBhMC
VVMxDzANBgNVBAoMBlNQSUZGRTEVMBMGA1UEAwwMdGVzdC1yb290LWNhMB4XDTIw
MDUyODA1NTgxOVoXDTMwMDUyNjA1NTgxOVowPTELMAkGA1UEBhMCVVMxDzANBgNV
BAoMBlNQSUZGRTEdMBsGA1UEAwwUdGVzdC1pbnRlcm1lZGlhdGUtY2EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQl25uLXYCtUuC56HBfiuSPRihZh+XZFe1azAt8
m4JFFQE0MKYBGmuv+dtxbb7S1DWDIWe+/TgnwPlvPZ2fG8H1ozIwMDAgBgNVHREE
GTAXhhVzcGlmZmU6Ly9pbnRlcm1lZGlhdGUwDAYDVR0TBAUwAwEB/zAJBgcqhkjO
PQQBA0kAMEYCIQC75fPz270uBP654XhWXTzAv+pEy2i3tUIbeinFXuhhYQIhAJdm
Et2IvChBiw2vII7Be7LUQq20qF6YIWaZbIYVLwD3
-----END CERTIFICATE-----`
)

var (
	ctx      = context.Background()
	td       = spiffeid.RequireTrustDomainFromString("example.org")
	serverID = idutil.RequireServerID(td)
)

func TestGetInfo(t *testing.T) {
	// Create root CA
	ca := testca.New(t, td)
	x509SVID := ca.CreateX509SVID(serverID)
	x509SVIDState := svid.State{
		SVID: x509SVID.Certificates,
		Key:  x509SVID.PrivateKey.(*ecdsa.PrivateKey),
	}
	x509SVIDChain := []*debugv1.GetInfoResponse_Cert{
		{
			Id: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/spire/server",
			},
			ExpiresAt: x509SVID.Certificates[0].NotAfter.Unix(),
			Subject:   x509SVID.Certificates[0].Subject.String(),
		},
		{
			ExpiresAt: ca.X509Authorities()[0].NotAfter.Unix(),
			Subject:   ca.X509Authorities()[0].Subject.String(),
		},
	}

	// Create intermediate with SPIFFE ID and subject
	now := time.Now()
	intermediateCANoAfter := now.Add(2 * time.Minute)
	intermediateCA := ca.ChildCA(testca.WithID(td.ID()),
		testca.WithLifetime(now, intermediateCANoAfter),
		testca.WithSubject(pkix.Name{CommonName: "UPSTREAM-1"}))

	// Create SVID with intermediate
	svidWithIntermediate := intermediateCA.CreateX509SVID(serverID)
	stateWithIntermediate := svid.State{
		SVID: svidWithIntermediate.Certificates,
		Key:  svidWithIntermediate.PrivateKey.(*ecdsa.PrivateKey),
	}
	// Manually create SVID chain with intermediate
	svidWithIntermediateChain := []*debugv1.GetInfoResponse_Cert{
		{
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/server"},
			ExpiresAt: svidWithIntermediate.Certificates[0].NotAfter.Unix(),
			Subject:   svidWithIntermediate.Certificates[0].Subject.String(),
		},
		{
			Id:        &types.SPIFFEID{TrustDomain: "example.org"},
			ExpiresAt: intermediateCANoAfter.Unix(),
			Subject:   "CN=UPSTREAM-1",
		},
		{
			ExpiresAt: ca.X509Authorities()[0].NotAfter.Unix(),
			Subject:   ca.X509Authorities()[0].Subject.String(),
		},
	}

	// Registration entries to create
	registrationEntries := []*common.RegistrationEntry{
		{
			ParentId: "spiffe://example.org/spire/agent/a1",
			SpiffeId: "spiffe://example.org/foo",
			Selectors: []*common.Selector{
				{Type: "a", Value: "1"},
			},
		},
		{
			ParentId: "spiffe://example.org/spire/agent/a1",
			SpiffeId: "spiffe://example.org/bar",
			Selectors: []*common.Selector{
				{Type: "b", Value: "2"},
			},
		},
	}

	// Attested nodes to create
	attestedNodes := []*common.AttestedNode{
		{
			SpiffeId:            "spiffe://example.org/spire/agent/a1",
			AttestationDataType: "t1",
			CertSerialNumber:    "12345",
			CertNotAfter:        now.Add(-time.Hour).Unix(),
		},
		{
			SpiffeId:            "spiffe://example.org/spire/agent/a2",
			AttestationDataType: "t2",
			CertSerialNumber:    "6789",
			CertNotAfter:        now.Add(time.Hour).Unix(),
		},
	}

	// Parse federated  bundle into DER raw
	federatedBundle, err := pemutil.ParseCertificate([]byte(federatedBundle))
	require.NoError(t, err)
	commonFederatedBundle := &common.Bundle{
		TrustDomainId: "spiffe://domain.io",
		RootCas: []*common.Certificate{
			{
				DerBytes: federatedBundle.Raw,
			},
		},
	}

	// x509SVID common bundle
	commonCABundle := &common.Bundle{
		TrustDomainId: td.IDString(),
		RootCas: []*common.Certificate{
			{
				DerBytes: x509util.DERFromCertificates(ca.X509Authorities()),
			},
		},
	}

	// Intermediate common bundle
	commonIntermediateBundle := &common.Bundle{
		TrustDomainId: td.IDString(),
		RootCas: []*common.Certificate{
			{
				DerBytes: x509util.DERFromCertificates(intermediateCA.X509Authorities()),
			},
		},
	}

	_, expectParseErr := x509.ParseCertificate([]byte{11, 22, 33, 44})
	require.Error(t, expectParseErr)

	for _, tt := range []struct {
		name string

		code         codes.Code
		err          string
		dsErrors     []error
		expectResp   *debugv1.GetInfoResponse
		expectedLogs []spiretest.LogEntry
		// Time to add to clock.Mock
		addToClk  time.Duration
		initCache bool

		attestedNodes       []*common.AttestedNode
		bundles             []*common.Bundle
		registrationEntries []*common.RegistrationEntry

		state svid.State
	}{
		{
			name: "regular SVID",
			expectResp: &debugv1.GetInfoResponse{
				FederatedBundlesCount: 1,
				SvidChain:             x509SVIDChain,
			},
			bundles: []*common.Bundle{commonCABundle},
			state:   x509SVIDState,
		},
		{
			name: "SVID with intermediate",
			expectResp: &debugv1.GetInfoResponse{
				FederatedBundlesCount: 1,
				SvidChain:             svidWithIntermediateChain,
			},
			bundles: []*common.Bundle{commonIntermediateBundle},
			state:   stateWithIntermediate,
		},
		{
			name: "complete data",
			expectResp: &debugv1.GetInfoResponse{
				SvidChain:             x509SVIDChain,
				AgentsCount:           2,
				EntriesCount:          2,
				FederatedBundlesCount: 2,
			},
			bundles: []*common.Bundle{
				commonCABundle,
				commonFederatedBundle,
			},
			registrationEntries: registrationEntries,
			attestedNodes:       attestedNodes,
			state:               x509SVIDState,
		},
		{
			name: "response from cache",
			// No registration entries and attested nodes expected, those are created after cache is initiated
			expectResp: &debugv1.GetInfoResponse{
				SvidChain:             x509SVIDChain,
				FederatedBundlesCount: 2,
			},
			bundles: []*common.Bundle{
				commonCABundle,
				commonFederatedBundle,
			},
			registrationEntries: registrationEntries,
			attestedNodes:       attestedNodes,
			state:               x509SVIDState,
			initCache:           true,
		},
		{
			name: "expired cache",
			// Actual state expected after expiration
			expectResp: &debugv1.GetInfoResponse{
				SvidChain:             x509SVIDChain,
				AgentsCount:           2,
				EntriesCount:          2,
				FederatedBundlesCount: 2,
				// Seconds added to clk
				Uptime: 5,
			},
			bundles: []*common.Bundle{
				commonCABundle,
				commonFederatedBundle,
			},
			addToClk:            5 * time.Second,
			registrationEntries: registrationEntries,
			attestedNodes:       attestedNodes,
			state:               x509SVIDState,
			initCache:           true,
		},
		{
			name:     "failed to count attested nodes",
			dsErrors: []error{errors.New("some error")},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to count agents",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to count agents: some error",
		},
		{
			name:     "failed to count entries",
			dsErrors: []error{nil, errors.New("some error")},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to count entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to count entries: some error",
		},
		{
			name:     "failed to count bundles",
			dsErrors: []error{nil, nil, errors.New("some error")},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to count bundles",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to count bundles: some error",
		},
		{
			name:     "failed to fetch trustdomain bundle",
			dsErrors: []error{nil, nil, nil, errors.New("some error")},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch trust domain bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to fetch trust domain bundle: some error",
		},
		{
			name: "no bundle for trust domain",
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Trust domain bundle not found",
				},
			},
			code:  codes.NotFound,
			err:   "trust domain bundle not found",
			state: x509SVIDState,
		},
		{
			name: "malformed trust domain bundle",
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to parse bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: expectParseErr.Error()},
				},
			},
			bundles: []*common.Bundle{
				{
					TrustDomainId: td.IDString(),
					RootCas:       []*common.Certificate{{DerBytes: []byte{11, 22, 33, 44}}},
				},
			},
			code:  codes.Internal,
			err:   "failed to parse bundle: x509: malformed certificate",
			state: x509SVIDState,
		},
		{
			name: "x509 verify failed",
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed verification against bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: "x509svid: could not verify leaf certificate: x509: certificate signed by unknown authority",
					},
				},
			},
			bundles: []*common.Bundle{
				{
					TrustDomainId: td.IDString(),
					RootCas:       []*common.Certificate{{DerBytes: federatedBundle.Raw}},
				},
			},
			code:  codes.Internal,
			err:   "failed verification against bundle: x509svid: could not verify leaf certificate: x509: certificate signed by unknown authority",
			state: x509SVIDState,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			for _, err := range tt.dsErrors {
				test.ds.AppendNextError(err)
			}
			test.so.state = tt.state
			for _, bundle := range tt.bundles {
				_, err := test.ds.CreateBundle(ctx, bundle)
				require.NoError(t, err)
			}

			if tt.initCache {
				test.so.state = tt.state
				_, err := test.client.GetInfo(ctx, &debugv1.GetInfoRequest{})
				require.NoError(t, err)
			}
			test.clk.Add(tt.addToClk)

			// Init datastore
			for _, node := range tt.attestedNodes {
				_, err := test.ds.CreateAttestedNode(ctx, node)
				require.NoError(t, err)
			}
			for _, entry := range tt.registrationEntries {
				_, err := test.ds.CreateRegistrationEntry(ctx, entry)
				require.NoError(t, err)
			}

			// Call client
			resp, err := test.client.GetInfo(ctx, &debugv1.GetInfoRequest{})
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)
			if tt.err != "" {
				spiretest.AssertGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}
			require.NoError(t, err)

			spiretest.RequireProtoEqual(t, tt.expectResp, resp)
		})
	}
}

type serviceTest struct {
	client debugv1.DebugClient
	done   func()

	clk     *clock.Mock
	logHook *test.Hook
	ds      *fakedatastore.DataStore
	so      *fakeObserver
	uptime  *fakeUptime
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	clk := clock.NewMock()
	ds := fakedatastore.New(t)
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	fakeUptime := &fakeUptime{
		start: clk.Now(),
		clk:   clk,
	}
	observer := &fakeObserver{}

	service := debug.New(debug.Config{
		Clock:        clk,
		DataStore:    ds,
		SVIDObserver: observer,
		TrustDomain:  td,
		Uptime:       fakeUptime.uptime,
	})

	test := &serviceTest{
		clk:     clk,
		ds:      ds,
		logHook: logHook,
		so:      observer,
		uptime:  fakeUptime,
	}

	registerFn := func(s grpc.ServiceRegistrar) {
		debug.RegisterService(s, service)
	}
	overrideContext := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}

	server := grpctest.StartServer(t, registerFn, grpctest.OverrideContext(overrideContext))

	conn := server.Dial(t)

	test.done = server.Stop
	test.client = debugv1.NewDebugClient(conn)

	return test
}

type fakeObserver struct {
	state svid.State
}

func (o *fakeObserver) State() svid.State {
	return o.state
}

type fakeUptime struct {
	start time.Time
	clk   *clock.Mock
}

func (f *fakeUptime) uptime() time.Duration {
	return f.clk.Now().Sub(f.start)
}
