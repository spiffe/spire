package trustdomain_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/api/trustdomain/v1"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx         = context.Background()
	td          = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTd = spiffeid.RequireTrustDomainFromString("domain1.org")
)

func TestBatchCreateFederationRelationship(t *testing.T) {
	// testca.New()
	ca := testca.New(t, td)
	caRaw := ca.X509Authorities()[0].Raw

	bundleEndpointURL, err := url.Parse("https//some.url/url")
	require.NoError(t, err)

	defaultFederationRelationship := &datastore.FederationRelationship{
		TrustDomain:           federatedTd,
		BundleEndpointURL:     bundleEndpointURL,
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}
	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)

	sb := &common.Bundle{
		TrustDomainId: "spiffe://domain.test",
		RefreshHint:   60,
		RootCas:       []*common.Certificate{{DerBytes: caRaw}},
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "key-id-1",
				NotAfter:  1590514224,
				PkixBytes: pkixBytes,
			},
		},
	}
	pkixHashed := api.HashByte(pkixBytes)
	x509AuthorityHashed := api.HashByte(caRaw)

	defaultBundle, err := api.BundleToProto(sb)
	require.NoError(t, err)

	for _, tt := range []struct {
		name            string
		expectLogs      []spiretest.LogEntry
		expectResults   []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result
		outputMask      *types.FederationRelationshipMask
		req             []*types.FederationRelationship
		expectDSErr     error
		customDSReponse *datastore.FederationRelationship
	}{
		{
			name: "creating multiple trustdomains",
			req: []*types.FederationRelationship{
				{
					TrustDomain:           "domain.test",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint",
				},
				{
					TrustDomain:           "domain2.test",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint2",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "federation relationship created",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "domain.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "domain.test",
						telemetry.Type:                  "audit",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "federation relationship created",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "domain2.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/bundleendpoint2",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "domain2.test",
						telemetry.Type:                  "audit",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:           "domain.test",
						BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint",
						BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					},
				},
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:           "domain2.test",
						BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint2",
						BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					},
				},
			},
		},
		{
			name: "create HttpsSpiffe relationship",
			req: []*types.FederationRelationship{
				{
					TrustDomain:       "domain.test",
					BundleEndpointUrl: "https://federated-td-web.org/bundleendpoint",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://domain.test/endpoint",
							Bundle:           defaultBundle,
						},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "federation relationship created",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "domain.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile:     "https_spiffe",
						telemetry.BundleEndpointURL:         "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                    "success",
						telemetry.TrustDomainID:             "domain.test",
						telemetry.Type:                      "audit",
						telemetry.EndpointSpiffeID:          "spiffe://domain.test/endpoint",
						"jwt_authority_expires_at.0":        "1590514224",
						"jwt_authority_key_id.0":            "key-id-1",
						"jwt_authority_public_key_sha256.0": pkixHashed,
						telemetry.RefreshHint:               "60",
						telemetry.SequenceNumber:            "0",
						"x509_authorities_asn1_sha256.0":    x509AuthorityHashed,
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:       "domain.test",
						BundleEndpointUrl: "https://federated-td-web.org/bundleendpoint",
						BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
							HttpsSpiffe: &types.HTTPSSPIFFEProfile{
								EndpointSpiffeId: "spiffe://domain.test/endpoint",
								Bundle:           defaultBundle,
							},
						},
					},
				},
			},
		},
		{
			name: "using output mask",
			req: []*types.FederationRelationship{
				{
					TrustDomain:           "domain.test",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint",
				},
			},
			// Mask with all false
			outputMask: &types.FederationRelationshipMask{},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "federation relationship created",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "domain.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "domain.test",
						telemetry.Type:                  "audit",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain: "domain.test",
					},
				},
			},
		},
		{
			name: "failed to parse proto",
			req: []*types.FederationRelationship{
				{
					TrustDomain:           "no a td",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert federation relationship",
					Data: logrus.Fields{
						logrus.ErrorKey: "failed to parse trust domain: spiffeid: unable to parse: parse \"spiffe://no a td\": invalid character \" \" in host name",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/bundleendpoint",
						telemetry.TrustDomainID:         "no a td",
						telemetry.Type:                  "audit",
						telemetry.Status:                "error",
						telemetry.StatusCode:            "InvalidArgument",
						telemetry.StatusMessage:         "failed to convert federation relationship: failed to parse trust domain: spiffeid: unable to parse: parse \"spiffe://no a td\": invalid character \" \" in host name",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: `failed to convert federation relationship: failed to parse trust domain: spiffeid: unable to parse: parse "spiffe://no a td": invalid character " " in host name`,
					},
				},
			},
		},
		{
			name: "ds fails to create relationship",
			req: []*types.FederationRelationship{
				{
					TrustDomain:           "domain.test",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/bundleendpoint",
				},
			},
			expectDSErr: errors.New("oh no"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create federation relationship",
					Data: logrus.Fields{
						logrus.ErrorKey:         "oh no",
						telemetry.TrustDomainID: "domain.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/bundleendpoint",
						telemetry.TrustDomainID:         "domain.test",
						telemetry.Type:                  "audit",
						telemetry.Status:                "error",
						telemetry.StatusCode:            "Internal",
						telemetry.StatusMessage:         "failed to create federation relationship: oh no",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to create federation relationship: oh no",
					},
				},
			},
		},
		{
			name: "failed to parse datastore response",
			req: []*types.FederationRelationship{
				{
					TrustDomain:       "domain.test",
					BundleEndpointUrl: "https://federated-td-web.org/bundleendpoint",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://domain.test/endpoint",
							Bundle:           defaultBundle,
						},
					},
				},
			},
			customDSReponse: &datastore.FederationRelationship{},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert datastore response",
					Data: logrus.Fields{
						logrus.ErrorKey:         "trust domain is required",
						telemetry.TrustDomainID: "domain.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile:     "https_spiffe",
						telemetry.BundleEndpointURL:         "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                    "error",
						telemetry.StatusCode:                "Internal",
						telemetry.StatusMessage:             "failed to convert datastore response: trust domain is required",
						telemetry.TrustDomainID:             "domain.test",
						telemetry.Type:                      "audit",
						telemetry.EndpointSpiffeID:          "spiffe://domain.test/endpoint",
						"jwt_authority_expires_at.0":        "1590514224",
						"jwt_authority_key_id.0":            "key-id-1",
						"jwt_authority_public_key_sha256.0": pkixHashed,
						telemetry.RefreshHint:               "60",
						telemetry.SequenceNumber:            "0",
						"x509_authorities_asn1_sha256.0":    x509AuthorityHashed,
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to convert datastore response: trust domain is required",
					},
				},
			},
		},
		{
			name: "trust domain already exists",
			req: []*types.FederationRelationship{
				{
					TrustDomain:           defaultFederationRelationship.TrustDomain.String(),
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/another",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create federation relationship",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "domain1.org",
						logrus.ErrorKey:         "rpc error: code = AlreadyExists desc = datastore-sql: UNIQUE constraint failed: federated_trust_domains.trust_domain",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/another",
						telemetry.Status:                "error",
						telemetry.TrustDomainID:         "domain1.org",
						telemetry.Type:                  "audit",
						telemetry.StatusCode:            "Internal",
						telemetry.StatusMessage:         "failed to create federation relationship: datastore-sql: UNIQUE constraint failed: federated_trust_domains.trust_domain",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to create federation relationship: datastore-sql: UNIQUE constraint failed: federated_trust_domains.trust_domain",
					},
				},
			},
		},
		{
			name: "using server trust domain",
			req: []*types.FederationRelationship{
				{
					TrustDomain:           td.String(),
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					BundleEndpointUrl:     "https://federated-td-web.org/another",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: unable to create federation relationship for server trust domain",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "example.org",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/another",
						telemetry.Status:                "error",
						telemetry.TrustDomainID:         "example.org",
						telemetry.Type:                  "audit",
						telemetry.StatusCode:            "InvalidArgument",
						telemetry.StatusMessage:         "unable to create federation relationship for server trust domain",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "unable to create federation relationship for server trust domain",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := newFakeDS(t)
			ds.customDSResponse = tt.customDSReponse

			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			// Create default relationship
			createTestRelationships(t, ds, defaultFederationRelationship)

			// Setup fake
			ds.AppendNextError(tt.expectDSErr)

			// Batch create
			resp, err := test.client.BatchCreateFederationRelationship(ctx, &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationship: tt.req,
				OutputMask:             tt.outputMask,
			})

			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

			spiretest.AssertProtoEqual(t, &trustdomainv1.BatchCreateFederationRelationshipResponse{
				Results: tt.expectResults,
			}, resp)
		})
	}
}

func createTestRelationships(t *testing.T, ds datastore.DataStore, relationships ...*datastore.FederationRelationship) map[string]*datastore.FederationRelationship {
	frMap := make(map[string]*datastore.FederationRelationship)

	for _, fr := range relationships {
		dRelationship, err := ds.CreateFederationRelationship(ctx, fr)
		require.NoError(t, err)

		frMap[dRelationship.TrustDomain.String()] = fr
	}

	return frMap
}

type serviceTest struct {
	client  trustdomainv1.TrustDomainClient
	ds      datastore.DataStore
	logHook *test.Hook
	done    func()
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T, ds datastore.DataStore) *serviceTest {
	service := trustdomain.New(trustdomain.Config{
		DataStore:   ds,
		TrustDomain: td,
	})

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	registerFn := func(s *grpc.Server) {
		trustdomain.RegisterService(s, service)
	}

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
	}

	ppMiddleware := middleware.Preprocess(func(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
		ctx = rpccontext.WithLogger(ctx, log)

		return ctx, nil
	})

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		ppMiddleware,
		// Add audit log with uds tracking disabled
		middleware.WithAuditLog(false),
	))

	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	conn, done := spiretest.NewAPIServerWithMiddleware(t, registerFn, server)
	test.done = done
	test.client = trustdomainv1.NewTrustDomainClient(conn)

	return test
}

type fakeDS struct {
	*fakedatastore.DataStore

	customDSResponse *datastore.FederationRelationship
}

func newFakeDS(t *testing.T) *fakeDS {
	return &fakeDS{
		DataStore: fakedatastore.New(t),
	}
}

func (d *fakeDS) CreateFederationRelationship(c context.Context, fr *datastore.FederationRelationship) (*datastore.FederationRelationship, error) {
	if d.customDSResponse != nil {
		return d.customDSResponse, nil
	}

	return d.DataStore.CreateFederationRelationship(ctx, fr)
}
