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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx         = context.Background()
	td          = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTd = spiffeid.RequireTrustDomainFromString("domain1.org")
)

func TestListFederationRelationships(t *testing.T) {
	ds := newFakeDS(t)
	test := setupServiceTest(t, ds)
	defer test.Cleanup()

	fr1 := &types.FederationRelationship{
		TrustDomain:       "example-1.org",
		BundleEndpointUrl: "https://endpoint-server-1/path",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://domain.test/endpoint-server",
				Bundle: &types.Bundle{
					TrustDomain: "example-1.org",
				},
			},
		},
	}
	dsFR1, err := api.ProtoToFederationRelationship(fr1)
	require.NoError(t, err)
	_, err = ds.CreateFederationRelationship(ctx, dsFR1)
	require.NoError(t, err)

	fr2 := &types.FederationRelationship{
		TrustDomain:       "example-2.org",
		BundleEndpointUrl: "https://endpoint-server-2/path",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{
			HttpsWeb: &types.HTTPSWebProfile{},
		},
	}

	dsFR2, err := api.ProtoToFederationRelationship(fr2)
	require.NoError(t, err)
	_, err = ds.CreateFederationRelationship(ctx, dsFR2)
	require.NoError(t, err)

	fr3 := &types.FederationRelationship{
		TrustDomain:       "example-3.org",
		BundleEndpointUrl: "https://endpoint-server-3/path",
		BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{
			HttpsWeb: &types.HTTPSWebProfile{},
		},
	}
	dsFR3, err := api.ProtoToFederationRelationship(fr3)
	require.NoError(t, err)
	_, err = ds.CreateFederationRelationship(ctx, dsFR3)
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		code        codes.Code
		err         string
		expectDSErr error
		expectPages [][]*types.FederationRelationship
		expectLogs  [][]spiretest.LogEntry
		outputMask  *types.FederationRelationshipMask
		pageSize    int32
	}{
		{
			name:        "all federation relationships at once with no mask",
			expectPages: [][]*types.FederationRelationship{{fr1, fr2, fr3}},
			expectLogs: [][]spiretest.LogEntry{
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status: "success",
							telemetry.Type:   "audit",
						},
					},
				},
			},
		},
		{
			name:        "all federation relationships at once with most permissive mask",
			expectPages: [][]*types.FederationRelationship{{fr1, fr2, fr3}},
			outputMask: &types.FederationRelationshipMask{
				BundleEndpointUrl:     true,
				BundleEndpointProfile: true,
			},
			expectLogs: [][]spiretest.LogEntry{
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status: "success",
							telemetry.Type:   "audit",
						},
					},
				},
			},
		},
		{
			name:        "all federation relationships at once filtered by mask",
			expectPages: [][]*types.FederationRelationship{{fr1, fr2, fr3}},
			outputMask: &types.FederationRelationshipMask{
				BundleEndpointUrl:     false,
				BundleEndpointProfile: false,
			},
			expectLogs: [][]spiretest.LogEntry{
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status: "success",
							telemetry.Type:   "audit",
						},
					},
				},
			},
		},
		{
			name: "page federation relationships",
			expectPages: [][]*types.FederationRelationship{
				{fr1, fr2},
				{fr3},
				{},
			},
			pageSize: 2,
			expectLogs: [][]spiretest.LogEntry{
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status: "success",
							telemetry.Type:   "audit",
						},
					},
				},
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status: "success",
							telemetry.Type:   "audit",
						},
					},
				},
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status: "success",
							telemetry.Type:   "audit",
						},
					},
				},
			},
		},
		{
			name: "datastore failure",

			err:         "failed to list federation relationships: oh no",
			expectDSErr: errors.New("oh no"),
			code:        codes.Internal,
			expectLogs: [][]spiretest.LogEntry{
				{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:        "error",
							telemetry.Type:          "audit",
							telemetry.StatusCode:    "Internal",
							telemetry.StatusMessage: "failed to list federation relationships: oh no",
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			ds.AppendNextError(tt.expectDSErr)

			page := 0
			var pageToken string
			var actualPages [][]*types.FederationRelationship
			for {
				resp, err := test.client.ListFederationRelationships(ctx, &trustdomainv1.ListFederationRelationshipsRequest{
					OutputMask: tt.outputMask,
					PageSize:   tt.pageSize,
					PageToken:  pageToken,
				})
				spiretest.AssertLastLogs(t, test.logHook.AllEntries(), tt.expectLogs[page])
				page++
				if tt.err != "" {
					spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
					require.Nil(t, resp)

					return
				}
				require.NoError(t, err)
				require.NotNil(t, resp)
				actualPages = append(actualPages, resp.FederationRelationships)
				require.LessOrEqual(t, len(actualPages), page, "got more pages than expected")
				pageToken = resp.NextPageToken
				if pageToken == "" {
					break
				}
			}

			require.Len(t, actualPages, len(tt.expectPages), "unexpected number of federation relationships pages")
			for i, actualPage := range actualPages {
				expectPage := tt.expectPages[i]
				require.Len(t, actualPage, len(expectPage), "unexpected number of federation relationships in page")

				for j, actualFR := range actualPage {
					expectFR := expectPage[j]
					assertFederationRelationshipWithMask(t, expectFR, actualFR, tt.outputMask)
				}
			}
		})
	}
}

func TestBatchCreateFederationRelationship(t *testing.T) {
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
		name             string
		expectLogs       []spiretest.LogEntry
		expectResults    []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result
		outputMask       *types.FederationRelationshipMask
		req              []*types.FederationRelationship
		expectDSErr      error
		customDSResponse *datastore.FederationRelationship
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
					Message: "Federation relationship created",
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
					Message: "Federation relationship created",
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
					Message: "Federation relationship created",
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
					Message: "Federation relationship created",
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
			customDSResponse: &datastore.FederationRelationship{},
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
			ds.customDSResponse = tt.customDSResponse

			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			// Create default relationship
			createTestRelationships(t, ds, defaultFederationRelationship)

			// Setup fake
			ds.AppendNextError(tt.expectDSErr)

			// Batch create
			resp, err := test.client.BatchCreateFederationRelationship(ctx, &trustdomainv1.BatchCreateFederationRelationshipRequest{
				FederationRelationships: tt.req,
				OutputMask:              tt.outputMask,
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

func TestBatchDeleteFederationRelationship(t *testing.T) {
	ca := testca.New(t, td)
	caRaw := ca.X509Authorities()[0].Raw

	fooURL, err := url.Parse("https://foo.test/path")
	require.NoError(t, err)
	fooFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("foo.test"),
		BundleEndpointURL:     fooURL,
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}

	barURL, err := url.Parse("https://bar.test/path")
	require.NoError(t, err)
	barFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
		BundleEndpointURL:     barURL,
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/endpoint"),
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://bar.test",
			RootCas: []*common.Certificate{
				{
					DerBytes: caRaw,
				},
			},
			RefreshHint: 60,
		},
	}

	bazURL, err := url.Parse("https://baz.test/path")
	require.NoError(t, err)
	bazFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("baz.test"),
		BundleEndpointURL:     bazURL,
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}

	allRelationships := []string{fooFR.TrustDomain.String(), barFR.TrustDomain.String(), bazFR.TrustDomain.String()}
	for _, tt := range []struct {
		name            string
		dsError         error
		expectDs        []string
		expectResults   []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result
		reqTrustDomains []string
		expectLogs      []spiretest.LogEntry
	}{
		{
			name:            "delete multiple trustdomains",
			reqTrustDomains: []string{barFR.TrustDomain.String(), "not.found", bazFR.TrustDomain.String()},
			expectDs:        []string{fooFR.TrustDomain.String()},
			expectResults: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
				{
					Status:      api.OK(),
					TrustDomain: "bar.test",
				},
				{
					Status: &types.Status{
						Code:    int32(codes.NotFound),
						Message: "federation relationship not found",
					},
					TrustDomain: "not.found",
				},
				{
					Status:      api.OK(),
					TrustDomain: "baz.test",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship deleted",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "bar.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.TrustDomainID: "bar.test",
						telemetry.Type:          "audit",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Federation relationship not found",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "not.found",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.TrustDomainID: "not.found",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "federation relationship not found",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship deleted",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "baz.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.TrustDomainID: "baz.test",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{

			name:            "empty trust domain",
			reqTrustDomains: []string{""},
			expectDs:        allRelationships,
			expectResults: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "missing trust domain",
					},
					TrustDomain: "",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: missing trust domain",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.TrustDomainID: "",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "missing trust domain",
					},
				},
			},
		},
		{

			name:            "malformed trust domain",
			reqTrustDomains: []string{"https://foot.test"},
			expectDs:        allRelationships,
			expectResults: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to parse trust domain: spiffeid: invalid scheme",
					},
					TrustDomain: "https://foot.test",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse trust domain",
					Data: logrus.Fields{
						logrus.ErrorKey:         "spiffeid: invalid scheme",
						telemetry.TrustDomainID: "https://foot.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.TrustDomainID: "https://foot.test",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "failed to parse trust domain: spiffeid: invalid scheme",
					},
				},
			},
		},
		{
			name:            "not found",
			reqTrustDomains: []string{"not.found"},
			expectDs:        allRelationships,
			expectResults: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.NotFound),
						Message: "federation relationship not found",
					},
					TrustDomain: "not.found",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Federation relationship not found",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "not.found",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.TrustDomainID: "not.found",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "federation relationship not found",
					},
				},
			},
		},
		{
			name:            "DS fails",
			reqTrustDomains: []string{fooFR.TrustDomain.String()},
			dsError:         errors.New("oh! no"),
			expectDs:        allRelationships,
			expectResults: []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to delete federation relationship: oh! no",
					},
					TrustDomain: "foo.test",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to delete federation relationship",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "foo.test",
						logrus.ErrorKey:         "oh! no",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.TrustDomainID: "foo.test",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to delete federation relationship: oh! no",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := fakedatastore.New(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			createTestRelationships(t, ds, fooFR, barFR, bazFR)
			ds.SetNextError(tt.dsError)

			resp, err := test.client.BatchDeleteFederationRelationship(ctx, &trustdomainv1.BatchDeleteFederationRelationshipRequest{
				TrustDomains: tt.reqTrustDomains,
			})
			require.NoError(t, err)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			spiretest.AssertProtoEqual(t, &trustdomainv1.BatchDeleteFederationRelationshipResponse{
				Results: tt.expectResults,
			}, resp)

			// Validate DS contains expected federation relationships
			listResp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{})
			require.NoError(t, err)

			var tds []string
			for _, fr := range listResp.FederationRelationships {
				tds = append(tds, fr.TrustDomain.String())
			}
			require.Equal(t, tt.expectDs, tds)
		})
	}
}

func TestBatchUpdateFederationRelationship(t *testing.T) {
	ca := testca.New(t, td)
	caRaw := ca.X509Authorities()[0].Raw

	newCA := testca.New(t, td)
	newCARaw := newCA.X509Authorities()[0].Raw

	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)

	fooURL, err := url.Parse("https://foo.test/path")
	require.NoError(t, err)
	fooFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("foo.test"),
		BundleEndpointURL:     fooURL,
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}
	newFooURL, err := url.Parse("https://foo.test/newpath")
	require.NoError(t, err)

	barURL, err := url.Parse("https://bar.test/path")
	require.NoError(t, err)
	barFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
		BundleEndpointURL:     barURL,
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/endpoint"),
		Bundle: &common.Bundle{
			TrustDomainId: "spiffe://bar.test",
			RootCas: []*common.Certificate{
				{
					DerBytes: caRaw,
				},
			},
			RefreshHint: 60,
		},
	}
	newBarURL, err := url.Parse("https://bar.test/newpath")
	require.NoError(t, err)

	for _, tt := range []struct {
		name             string
		dsError          error
		expectDSFR       []*datastore.FederationRelationship
		customDSResponse *datastore.FederationRelationship
		expectLogs       []spiretest.LogEntry
		expectResults    []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result
		inputMask        *types.FederationRelationshipMask
		outputMask       *types.FederationRelationshipMask
		reqFR            []*types.FederationRelationship
	}{
		{
			name: "multiples federation relationships",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:           "foo.test",
					BundleEndpointUrl:     "https://foo.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
				},
				{
					TrustDomain:           "not.found",
					BundleEndpointUrl:     "https://not.found/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
				},
				{
					TrustDomain:       "bar.test",
					BundleEndpointUrl: "https://bar.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://bar.test/updated",
							Bundle: &types.Bundle{
								TrustDomain:     "bar.test",
								X509Authorities: []*types.X509Certificate{{Asn1: newCARaw}},
								JwtAuthorities: []*types.JWTKey{
									{
										KeyId:     "key-id-1",
										ExpiresAt: 1590514224,
										PublicKey: pkixBytes,
									},
								},
								RefreshHint:    30,
								SequenceNumber: 1,
							},
						},
					},
				},
			},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:           "foo.test",
						BundleEndpointUrl:     "https://foo.test/newpath",
						BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					},
				},
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to update federation relationship: unable to fetch federation relationship: record not found",
					},
				},
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:       "bar.test",
						BundleEndpointUrl: "https://bar.test/newpath",
						BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
							HttpsSpiffe: &types.HTTPSSPIFFEProfile{
								EndpointSpiffeId: "spiffe://bar.test/updated",
								Bundle: &types.Bundle{
									TrustDomain: "bar.test",
									X509Authorities: []*types.X509Certificate{
										{
											Asn1: newCARaw,
										},
									},
									JwtAuthorities: []*types.JWTKey{
										{
											KeyId:     "key-id-1",
											ExpiresAt: 1590514224,
											PublicKey: pkixBytes,
										},
									},
									RefreshHint: 30,
								},
							},
						},
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("foo.test"),
					BundleEndpointURL:     newFooURL,
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				},
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
					BundleEndpointURL:     newBarURL,
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/updated"),
					Bundle: &common.Bundle{
						TrustDomainId: "spiffe://bar.test",
						RootCas:       []*common.Certificate{{DerBytes: newCARaw}},
						RefreshHint:   30,
						JwtSigningKeys: []*common.PublicKey{
							{
								PkixBytes: pkixBytes,
								Kid:       "key-id-1",
								NotAfter:  1590514224,
							},
						},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship updated",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "foo.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://foo.test/newpath",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "foo.test",
						telemetry.Type:                  "audit",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to update federation relationship",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "not.found",
						logrus.ErrorKey:         "rpc error: code = NotFound desc = unable to fetch federation relationship: record not found",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://not.found/newpath",
						telemetry.Status:                "error",
						telemetry.StatusCode:            "Internal",
						telemetry.StatusMessage:         "failed to update federation relationship: unable to fetch federation relationship: record not found",
						telemetry.TrustDomainID:         "not.found",
						telemetry.Type:                  "audit",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship updated",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "bar.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_spiffe",
						telemetry.BundleEndpointURL:     "https://bar.test/newpath",
						telemetry.Status:                "success",

						telemetry.EndpointSpiffeID:          "spiffe://bar.test/updated",
						"jwt_authority_expires_at.0":        "1590514224",
						"jwt_authority_key_id.0":            "key-id-1",
						"jwt_authority_public_key_sha256.0": api.HashByte(pkixBytes),
						telemetry.RefreshHint:               "30",
						telemetry.SequenceNumber:            "1",
						"x509_authorities_asn1_sha256.0":    api.HashByte(newCARaw),
						telemetry.TrustDomainID:             "bar.test",
						telemetry.Type:                      "audit",
					},
				},
			},
		},
		{
			name: "update https_spiffe to https_web",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:           "bar.test",
					BundleEndpointUrl:     "https://bar.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
				},
			},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:           "bar.test",
						BundleEndpointUrl:     "https://bar.test/newpath",
						BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship updated",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "bar.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://bar.test/newpath",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "bar.test",
						telemetry.Type:                  "audit",
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
					BundleEndpointURL:     newBarURL,
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				},
			},
		},
		{
			name: "input mask all false",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:       "bar.test",
					BundleEndpointUrl: "https://bar.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://bar.test/updated",
							Bundle: &types.Bundle{
								TrustDomain:     "bar.test",
								X509Authorities: []*types.X509Certificate{{Asn1: newCARaw}},
								JwtAuthorities: []*types.JWTKey{
									{
										KeyId:     "key-id-1",
										ExpiresAt: 1590514224,
										PublicKey: pkixBytes,
									},
								},
								RefreshHint:    30,
								SequenceNumber: 1,
							},
						},
					},
				},
			},
			inputMask: &types.FederationRelationshipMask{},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:       "bar.test",
						BundleEndpointUrl: "https://bar.test/path",
						BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
							HttpsSpiffe: &types.HTTPSSPIFFEProfile{
								EndpointSpiffeId: "spiffe://bar.test/endpoint",
								Bundle: &types.Bundle{
									TrustDomain: "bar.test",
									X509Authorities: []*types.X509Certificate{
										{
											Asn1: caRaw,
										},
									},
									RefreshHint: 60,
								},
							},
						},
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
					BundleEndpointURL:     barURL,
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/endpoint"),
					Bundle: &common.Bundle{
						TrustDomainId: "spiffe://bar.test",
						RootCas:       []*common.Certificate{{DerBytes: caRaw}},
						RefreshHint:   60,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship updated",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "bar.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.TrustDomainID: "bar.test",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name: "output mask all false",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:       "bar.test",
					BundleEndpointUrl: "https://bar.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://bar.test/updated",
							Bundle: &types.Bundle{
								TrustDomain:     "bar.test",
								X509Authorities: []*types.X509Certificate{{Asn1: newCARaw}},
								JwtAuthorities: []*types.JWTKey{
									{
										KeyId:     "key-id-1",
										ExpiresAt: 1590514224,
										PublicKey: pkixBytes,
									},
								},
								RefreshHint:    30,
								SequenceNumber: 1,
							},
						},
					},
				},
			},
			outputMask: &types.FederationRelationshipMask{},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain: "bar.test",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federation relationship updated",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "bar.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_spiffe",
						telemetry.BundleEndpointURL:     "https://bar.test/newpath",
						telemetry.Status:                "success",

						telemetry.EndpointSpiffeID:          "spiffe://bar.test/updated",
						"jwt_authority_expires_at.0":        "1590514224",
						"jwt_authority_key_id.0":            "key-id-1",
						"jwt_authority_public_key_sha256.0": api.HashByte(pkixBytes),
						telemetry.RefreshHint:               "30",
						telemetry.SequenceNumber:            "1",
						"x509_authorities_asn1_sha256.0":    api.HashByte(newCARaw),
						telemetry.TrustDomainID:             "bar.test",
						telemetry.Type:                      "audit",
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
					BundleEndpointURL:     newBarURL,
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/updated"),
					Bundle: &common.Bundle{
						TrustDomainId: "spiffe://bar.test",
						RootCas:       []*common.Certificate{{DerBytes: newCARaw}},
						RefreshHint:   30,
						JwtSigningKeys: []*common.PublicKey{
							{
								PkixBytes: pkixBytes,
								Kid:       "key-id-1",
								NotAfter:  1590514224,
							},
						},
					},
				},
			},
		},
		{
			name:    "Ds fails",
			dsError: errors.New("oh! no"),
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:           "foo.test",
					BundleEndpointUrl:     "https://foo.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
				},
			},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to update federation relationship: oh! no",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to update federation relationship",
					Data: logrus.Fields{
						logrus.ErrorKey:         "oh! no",
						telemetry.TrustDomainID: "foo.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://foo.test/newpath",
						telemetry.Status:                "error",
						telemetry.StatusCode:            "Internal",
						telemetry.StatusMessage:         "failed to update federation relationship: oh! no",
						telemetry.TrustDomainID:         "foo.test",
						telemetry.Type:                  "audit",
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("foo.test"),
					BundleEndpointURL:     fooURL,
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				},
			},
		},
		{
			name: "fail to parse DS response",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:           "foo.test",
					BundleEndpointUrl:     "https://foo.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{},
				},
			},
			customDSResponse: &datastore.FederationRelationship{},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to convert federation relationship to proto: trust domain is required",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert federation relationship to proto",
					Data: logrus.Fields{
						logrus.ErrorKey:         "trust domain is required",
						telemetry.TrustDomainID: "foo.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_web",
						telemetry.BundleEndpointURL:     "https://foo.test/newpath",
						telemetry.Status:                "error",
						telemetry.StatusCode:            "Internal",
						telemetry.StatusMessage:         "failed to convert federation relationship to proto: trust domain is required",
						telemetry.TrustDomainID:         "foo.test",
						telemetry.Type:                  "audit",
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("foo.test"),
					BundleEndpointURL:     fooURL,
					BundleEndpointProfile: datastore.BundleEndpointWeb,
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := newFakeDS(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			// Create initial entries
			createTestRelationships(t, ds, fooFR, barFR)

			// Setup DS
			ds.customDSResponse = tt.customDSResponse
			ds.SetNextError(tt.dsError)

			// Update federation relationships
			resp, err := test.client.BatchUpdateFederationRelationship(ctx, &trustdomainv1.BatchUpdateFederationRelationshipRequest{
				FederationRelationships: tt.reqFR,
				InputMask:               tt.inputMask,
				OutputMask:              tt.outputMask,
			})
			require.NoError(t, err)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			spiretest.AssertProtoEqual(t, &trustdomainv1.BatchUpdateFederationRelationshipResponse{
				Results: tt.expectResults,
			}, resp)

			// Check datastore
			// Unable to use Equal because it contains PROTO + regular structs
			for _, eachFR := range tt.expectDSFR {
				getResp, err := ds.FetchFederationRelationship(ctx, eachFR.TrustDomain)
				require.NoError(t, err)

				assert.Equal(t, eachFR.BundleEndpointProfile, getResp.BundleEndpointProfile)
				assert.Equal(t, eachFR.BundleEndpointURL.String(), getResp.BundleEndpointURL.String())
				assert.Equal(t, eachFR.EndpointSPIFFEID, getResp.EndpointSPIFFEID)
				assert.Equal(t, eachFR.TrustDomain, getResp.TrustDomain)
				spiretest.AssertProtoEqual(t, eachFR.Bundle, getResp.Bundle)
			}
		})
	}
}

func createTestRelationships(t *testing.T, ds datastore.DataStore, relationships ...*datastore.FederationRelationship) {
	for _, fr := range relationships {
		_, err := ds.CreateFederationRelationship(ctx, fr)
		require.NoError(t, err)
	}
}

func assertFederationRelationshipWithMask(t *testing.T, expected, actual *types.FederationRelationship, m *types.FederationRelationshipMask) {
	if expected == nil {
		require.Nil(t, actual)
		return
	}

	require.Equal(t, expected.TrustDomain, actual.TrustDomain)

	if m == nil || m.BundleEndpointProfile {
		require.Equal(t, expected.BundleEndpointProfile, actual.BundleEndpointProfile)
	} else {
		require.Nil(t, actual.BundleEndpointProfile)
	}

	if m == nil || m.BundleEndpointUrl {
		require.Equal(t, expected.BundleEndpointUrl, actual.BundleEndpointUrl)
	} else {
		require.Empty(t, actual.BundleEndpointUrl)
	}
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

func (d *fakeDS) UpdateFederationRelationship(c context.Context, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	if d.customDSResponse != nil {
		return d.customDSResponse, nil
	}

	return d.DataStore.UpdateFederationRelationship(ctx, fr, mask)
}
