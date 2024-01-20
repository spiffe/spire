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
	"github.com/spiffe/spire/test/grpctest"
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

func TestGetFederationRelationship(t *testing.T) {
	fr1 := &types.FederationRelationship{
		TrustDomain:       "example-1.org",
		BundleEndpointUrl: "https://endpoint-server-1/path",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://example-1.org/endpoint-server",
			},
		},
		TrustDomainBundle: &types.Bundle{
			TrustDomain: "example-1.org",
		},
	}

	dsFR1, err := api.ProtoToFederationRelationship(fr1)
	require.NoError(t, err)

	for _, tt := range []struct {
		name         string
		trustDomain  string
		code         codes.Code
		err          string
		expectDSErr  error
		expectResult *types.FederationRelationship
		expectLogs   []spiretest.LogEntry
		outputMask   *types.FederationRelationshipMask
	}{
		{
			name:         "successful fetch with no mask",
			trustDomain:  "example-1.org",
			expectResult: fr1,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.Type:          "audit",
						telemetry.TrustDomainID: "example-1.org",
					},
				},
			},
		},
		{
			name:         "successful fetch with mask",
			trustDomain:  "example-1.org",
			expectResult: fr1,
			outputMask: &types.FederationRelationshipMask{
				BundleEndpointUrl:     false,
				BundleEndpointProfile: false,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.Type:          "audit",
						telemetry.TrustDomainID: "example-1.org",
					},
				},
			},
		},
		{
			name:         "unsuccessful fetch with no mask",
			trustDomain:  "badexample-1.org",
			err:          "federation relationship does not exist",
			expectResult: fr1,
			code:         codes.NotFound,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.TrustDomainID: "badexample-1.org",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "federation relationship does not exist",
					},
				},
			},
		},
		{

			name:        "malformed trust domain",
			trustDomain: "https://foot.test",
			err:         "failed to parse trust domain: scheme is missing or invalid",
			code:        codes.InvalidArgument,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse trust domain",
					Data: logrus.Fields{
						logrus.ErrorKey: "scheme is missing or invalid",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.TrustDomainID: "https://foot.test",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "failed to parse trust domain: scheme is missing or invalid",
					},
				},
			},
		},
		{
			name:        "DS fails",
			trustDomain: "example-1.org",
			expectDSErr: errors.New("datastore error"),
			err:         "failed to fetch federation relationship: datastore error",
			code:        codes.Internal,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch federation relationship",
					Data: logrus.Fields{
						logrus.ErrorKey: "datastore error",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.TrustDomainID: "example-1.org",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to fetch federation relationship: datastore error",
					},
				},
			},
		},
		{
			name:        "Entry not found",
			trustDomain: "notfound.org",
			err:         "federation relationship does not exist",
			code:        codes.NotFound,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Federation relationship does not exist",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.TrustDomainID: "notfound.org",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "federation relationship does not exist",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := newFakeDS(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			_, err = ds.CreateFederationRelationship(ctx, dsFR1)
			require.NoError(t, err)

			ds.AppendNextError(tt.expectDSErr)

			resp, err := test.client.GetFederationRelationship(ctx, &trustdomainv1.GetFederationRelationshipRequest{
				TrustDomain: tt.trustDomain,
				OutputMask:  tt.outputMask,
			})
			spiretest.AssertLastLogs(t, test.logHook.AllEntries(), tt.expectLogs)

			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			if tt.expectResult != nil {
				assertFederationRelationshipWithMask(t, tt.expectResult, resp, tt.outputMask)
			} else {
				require.Nil(t, resp)
			}
		})
	}
}

func TestListFederationRelationships(t *testing.T) {
	ds := newFakeDS(t)
	test := setupServiceTest(t, ds)
	defer test.Cleanup()

	fr1 := &types.FederationRelationship{
		TrustDomain:       "example-1.org",
		BundleEndpointUrl: "https://endpoint-server-1/path",
		BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
			HttpsSpiffe: &types.HTTPSSPIFFEProfile{
				EndpointSpiffeId: "spiffe://example-1.org/endpoint-server",
			},
		},
		TrustDomainBundle: &types.Bundle{
			TrustDomain: "example-1.org",
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
		TrustDomainId:  "spiffe://domain.test",
		RefreshHint:    60,
		SequenceNumber: 42,
		RootCas:        []*common.Certificate{{DerBytes: caRaw}},
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
						},
					},
					TrustDomainBundle: defaultBundle,
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
						telemetry.BundleEndpointProfile:            "https_spiffe",
						telemetry.BundleEndpointURL:                "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                           "success",
						telemetry.TrustDomainID:                    "domain.test",
						telemetry.Type:                             "audit",
						telemetry.EndpointSpiffeID:                 "spiffe://domain.test/endpoint",
						"bundle_jwt_authority_expires_at.0":        "1590514224",
						"bundle_jwt_authority_key_id.0":            "key-id-1",
						"bundle_jwt_authority_public_key_sha256.0": pkixHashed,
						"bundle_refresh_hint":                      "60",
						"bundle_sequence_number":                   "42",
						"bundle_x509_authorities_asn1_sha256.0":    x509AuthorityHashed,
						"bundle_trust_domain_id":                   "domain.test",
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
							},
						},
						TrustDomainBundle: defaultBundle,
					},
				},
			},
		},
		{
			name: "trust domain bundle trust domain mismatch",
			req: []*types.FederationRelationship{
				{
					TrustDomain:       "other-domain.test",
					BundleEndpointUrl: "https://federated-td-web.org/bundleendpoint",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://other-domain.test/endpoint",
						},
					},
					TrustDomainBundle: defaultBundle,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert federation relationship",
					Data: logrus.Fields{
						telemetry.Error:         `trust domain bundle ("domain.test") must match the trust domain of the federation relationship ("other-domain.test")`,
						telemetry.TrustDomainID: "other-domain.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile:            "https_spiffe",
						telemetry.BundleEndpointURL:                "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                           "error",
						telemetry.StatusCode:                       "InvalidArgument",
						telemetry.StatusMessage:                    `failed to convert federation relationship: trust domain bundle ("domain.test") must match the trust domain of the federation relationship ("other-domain.test")`,
						telemetry.TrustDomainID:                    "other-domain.test",
						telemetry.Type:                             "audit",
						telemetry.EndpointSpiffeID:                 "spiffe://other-domain.test/endpoint",
						"bundle_jwt_authority_expires_at.0":        "1590514224",
						"bundle_jwt_authority_key_id.0":            "key-id-1",
						"bundle_jwt_authority_public_key_sha256.0": pkixHashed,
						"bundle_refresh_hint":                      "60",
						"bundle_sequence_number":                   "42",
						"bundle_x509_authorities_asn1_sha256.0":    x509AuthorityHashed,
						"bundle_trust_domain_id":                   "domain.test",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: `failed to convert federation relationship: trust domain bundle ("domain.test") must match the trust domain of the federation relationship ("other-domain.test")`,
					},
				},
			},
		},
		{
			name: "create HttpsSpiffe relationship without trust domain bundle",
			req: []*types.FederationRelationship{
				{
					TrustDomain:       "domain.test",
					BundleEndpointUrl: "https://federated-td-web.org/bundleendpoint",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://federated-td-web.org/endpoint",
						},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "bundle not found for the endpoint SPIFFE ID trust domain",
					Data: logrus.Fields{
						telemetry.TrustDomainID:    "domain.test",
						telemetry.EndpointSpiffeID: "spiffe://federated-td-web.org/endpoint",
					},
				},
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
						telemetry.BundleEndpointProfile: "https_spiffe",
						telemetry.BundleEndpointURL:     "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "domain.test",
						telemetry.Type:                  "audit",
						telemetry.EndpointSpiffeID:      "spiffe://federated-td-web.org/endpoint",
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
								EndpointSpiffeId: "spiffe://federated-td-web.org/endpoint",
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
						logrus.ErrorKey:         "failed to parse trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
						telemetry.TrustDomainID: "no a td",
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
						telemetry.StatusMessage:         "failed to convert federation relationship: failed to parse trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert federation relationship: failed to parse trust domain: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
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
						},
					},
					TrustDomainBundle: defaultBundle,
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
						telemetry.BundleEndpointProfile:            "https_spiffe",
						telemetry.BundleEndpointURL:                "https://federated-td-web.org/bundleendpoint",
						telemetry.Status:                           "error",
						telemetry.StatusCode:                       "Internal",
						telemetry.StatusMessage:                    "failed to convert datastore response: trust domain is required",
						telemetry.TrustDomainID:                    "domain.test",
						telemetry.Type:                             "audit",
						telemetry.EndpointSpiffeID:                 "spiffe://domain.test/endpoint",
						"bundle_jwt_authority_expires_at.0":        "1590514224",
						"bundle_jwt_authority_key_id.0":            "key-id-1",
						"bundle_jwt_authority_public_key_sha256.0": pkixHashed,
						"bundle_refresh_hint":                      "60",
						"bundle_sequence_number":                   "42",
						"bundle_trust_domain_id":                   "domain.test",
						"bundle_x509_authorities_asn1_sha256.0":    x509AuthorityHashed,
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
					TrustDomain:           defaultFederationRelationship.TrustDomain.Name(),
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
					TrustDomain:           td.Name(),
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

			var expectReloadCount int
			for _, result := range tt.expectResults {
				if result.Status.Code == 0 {
					expectReloadCount = 1
				}
			}
			assert.Equal(t, expectReloadCount, test.br.ReloadCount(), "unexpected reload count")
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
		TrustDomainBundle: &common.Bundle{
			TrustDomainId: "spiffe://bar.test",
			RootCas: []*common.Certificate{
				{
					DerBytes: caRaw,
				},
			},
			RefreshHint:    60,
			SequenceNumber: 42,
		},
	}

	bazURL, err := url.Parse("https://baz.test/path")
	require.NoError(t, err)
	bazFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("baz.test"),
		BundleEndpointURL:     bazURL,
		BundleEndpointProfile: datastore.BundleEndpointWeb,
	}

	allRelationships := []string{fooFR.TrustDomain.Name(), barFR.TrustDomain.Name(), bazFR.TrustDomain.Name()}
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
			reqTrustDomains: []string{barFR.TrustDomain.Name(), "not.found", bazFR.TrustDomain.Name()},
			expectDs:        []string{fooFR.TrustDomain.Name()},
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
						Message: "failed to parse trust domain: scheme is missing or invalid",
					},
					TrustDomain: "https://foot.test",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse trust domain",
					Data: logrus.Fields{
						logrus.ErrorKey:         "scheme is missing or invalid",
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
						telemetry.StatusMessage: "failed to parse trust domain: scheme is missing or invalid",
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
			reqTrustDomains: []string{fooFR.TrustDomain.Name()},
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

			var expectReloadCount int
			for _, result := range tt.expectResults {
				if result.Status.Code == 0 {
					expectReloadCount = 1
				}
			}
			assert.Equal(t, expectReloadCount, test.br.ReloadCount(), "unexpected reload count")

			// Validate DS contains expected federation relationships
			listResp, err := ds.ListFederationRelationships(ctx, &datastore.ListFederationRelationshipsRequest{})
			require.NoError(t, err)

			var tds []string
			for _, fr := range listResp.FederationRelationships {
				tds = append(tds, fr.TrustDomain.Name())
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
	barCommonBundle1 := &common.Bundle{
		TrustDomainId:  "spiffe://bar.test",
		RootCas:        []*common.Certificate{{DerBytes: caRaw}},
		RefreshHint:    60,
		SequenceNumber: 42,
	}

	barTypesBundle1 := &types.Bundle{
		TrustDomain:     "bar.test",
		X509Authorities: []*types.X509Certificate{{Asn1: caRaw}},
		RefreshHint:     60,
		SequenceNumber:  42,
	}

	barCommonBundle2 := &common.Bundle{
		TrustDomainId:  "spiffe://bar.test",
		RootCas:        []*common.Certificate{{DerBytes: newCARaw}},
		RefreshHint:    30,
		SequenceNumber: 20,
		JwtSigningKeys: []*common.PublicKey{
			{
				PkixBytes: pkixBytes,
				Kid:       "key-id-1",
				NotAfter:  1590514224,
			},
		},
	}

	barTypesBundle2 := &types.Bundle{
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
		SequenceNumber: 20,
	}

	barFR := &datastore.FederationRelationship{
		TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
		BundleEndpointURL:     barURL,
		BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
		EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/endpoint"),
		TrustDomainBundle:     barCommonBundle1,
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
			name: "multiple federation relationships",
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
						},
					},
					TrustDomainBundle: barTypesBundle2,
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
							},
						},
						TrustDomainBundle: barTypesBundle2,
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
					TrustDomainBundle:     barCommonBundle2,
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
						telemetry.BundleEndpointProfile:            "https_spiffe",
						telemetry.BundleEndpointURL:                "https://bar.test/newpath",
						telemetry.Status:                           "success",
						telemetry.EndpointSpiffeID:                 "spiffe://bar.test/updated",
						telemetry.TrustDomainID:                    "bar.test",
						telemetry.Type:                             "audit",
						"bundle_jwt_authority_expires_at.0":        "1590514224",
						"bundle_jwt_authority_key_id.0":            "key-id-1",
						"bundle_jwt_authority_public_key_sha256.0": api.HashByte(pkixBytes),
						"bundle_refresh_hint":                      "30",
						"bundle_sequence_number":                   "20",
						"bundle_x509_authorities_asn1_sha256.0":    api.HashByte(newCARaw),
						"bundle_trust_domain_id":                   "bar.test",
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
						TrustDomainBundle:     barTypesBundle1,
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
					TrustDomainBundle:     barCommonBundle1,
				},
			},
		},
		{
			name: "update to https_spiffe profile with bundle trust domain mismatch",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:       "foo.test",
					BundleEndpointUrl: "https://foo.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://foo.test/endpoint",
						},
					},
					TrustDomainBundle: &types.Bundle{
						TrustDomain: "baz.test",
					},
				},
			},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: `failed to convert federation relationship: trust domain bundle ("baz.test") must match the trust domain of the federation relationship ("foo.test")`,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert federation relationship",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "foo.test",
						telemetry.Error:         `trust domain bundle ("baz.test") must match the trust domain of the federation relationship ("foo.test")`,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.BundleEndpointProfile: "https_spiffe",
						telemetry.EndpointSpiffeID:      "spiffe://foo.test/endpoint",
						telemetry.BundleEndpointURL:     "https://foo.test/newpath",
						telemetry.Status:                "error",
						telemetry.StatusCode:            "InvalidArgument",
						telemetry.StatusMessage:         `failed to convert federation relationship: trust domain bundle ("baz.test") must match the trust domain of the federation relationship ("foo.test")`,
						telemetry.TrustDomainID:         "foo.test",
						telemetry.Type:                  "audit",
						"bundle_refresh_hint":           "0",
						"bundle_sequence_number":        "0",
						"bundle_trust_domain_id":        "baz.test",
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
			name: "update to non self-serving https_spiffe profile bundle not found",
			reqFR: []*types.FederationRelationship{
				{
					TrustDomain:       "foo.test",
					BundleEndpointUrl: "https://foo.test/newpath",
					BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
						HttpsSpiffe: &types.HTTPSSPIFFEProfile{
							EndpointSpiffeId: "spiffe://not.found/endpoint",
						},
					},
				},
			},
			expectResults: []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
				{
					Status: api.OK(),
					FederationRelationship: &types.FederationRelationship{
						TrustDomain:       "foo.test",
						BundleEndpointUrl: "https://foo.test/newpath",
						BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{
							HttpsSpiffe: &types.HTTPSSPIFFEProfile{
								EndpointSpiffeId: "spiffe://not.found/endpoint",
							},
						},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "bundle not found for the endpoint SPIFFE ID trust domain",
					Data: logrus.Fields{
						telemetry.EndpointSpiffeID: "spiffe://not.found/endpoint",
						telemetry.TrustDomainID:    "foo.test",
					},
				},
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
						telemetry.BundleEndpointProfile: "https_spiffe",
						telemetry.EndpointSpiffeID:      "spiffe://not.found/endpoint",
						telemetry.BundleEndpointURL:     "https://foo.test/newpath",
						telemetry.Status:                "success",
						telemetry.TrustDomainID:         "foo.test",
						telemetry.Type:                  "audit",
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("foo.test"),
					BundleEndpointURL:     newFooURL,
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://not.found/endpoint"),
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
						},
					},
					TrustDomainBundle: &types.Bundle{
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
							},
						},
						TrustDomainBundle: &types.Bundle{
							TrustDomain: "bar.test",
							X509Authorities: []*types.X509Certificate{
								{
									Asn1: caRaw,
								},
							},
							RefreshHint:    60,
							SequenceNumber: 42,
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
					TrustDomainBundle: &common.Bundle{
						TrustDomainId:  "spiffe://bar.test",
						RootCas:        []*common.Certificate{{DerBytes: caRaw}},
						RefreshHint:    60,
						SequenceNumber: 42,
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
						},
					},
					TrustDomainBundle: barTypesBundle2,
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
						telemetry.TrustDomainID:         "bar.test",
						telemetry.BundleEndpointProfile: "https_spiffe",
						telemetry.BundleEndpointURL:     "https://bar.test/newpath",
						telemetry.Status:                "success",

						telemetry.EndpointSpiffeID:                 "spiffe://bar.test/updated",
						"bundle_jwt_authority_expires_at.0":        "1590514224",
						"bundle_jwt_authority_key_id.0":            "key-id-1",
						"bundle_jwt_authority_public_key_sha256.0": api.HashByte(pkixBytes),
						"bundle_refresh_hint":                      "30",
						"bundle_sequence_number":                   "20",
						"bundle_x509_authorities_asn1_sha256.0":    api.HashByte(newCARaw),
						"bundle_trust_domain_id":                   "bar.test",
						telemetry.Type:                             "audit",
					},
				},
			},
			expectDSFR: []*datastore.FederationRelationship{
				{
					TrustDomain:           spiffeid.RequireTrustDomainFromString("bar.test"),
					BundleEndpointURL:     newBarURL,
					BundleEndpointProfile: datastore.BundleEndpointSPIFFE,
					EndpointSPIFFEID:      spiffeid.RequireFromString("spiffe://bar.test/updated"),
					TrustDomainBundle:     barCommonBundle2,
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

			var expectReloadCount int
			for _, result := range tt.expectResults {
				if result.Status.Code == 0 {
					expectReloadCount = 1
				}
			}
			assert.Equal(t, expectReloadCount, test.br.ReloadCount(), "unexpected reload count")

			// Check datastore
			// Unable to use Equal because it contains PROTO + regular structs
			for _, eachFR := range tt.expectDSFR {
				getResp, err := ds.FetchFederationRelationship(ctx, eachFR.TrustDomain)
				require.NoError(t, err)

				assert.Equal(t, eachFR.BundleEndpointProfile, getResp.BundleEndpointProfile)
				assert.Equal(t, eachFR.BundleEndpointURL.String(), getResp.BundleEndpointURL.String())
				assert.Equal(t, eachFR.EndpointSPIFFEID, getResp.EndpointSPIFFEID)
				assert.Equal(t, eachFR.TrustDomain, getResp.TrustDomain)
				spiretest.AssertProtoEqual(t, eachFR.TrustDomainBundle, getResp.TrustDomainBundle)
			}
		})
	}
}

func TestRefreshBundle(t *testing.T) {
	for _, tt := range []struct {
		name       string
		td         string
		expectCode codes.Code
		expectMsg  string
		expectLogs []spiretest.LogEntry
	}{
		{
			name:       "trust domain not managed",
			td:         "unknown.test",
			expectCode: codes.NotFound,
			expectMsg:  `no relationship with trust domain "unknown.test"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No relationship with trust domain \"unknown.test\"",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "unknown.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "no relationship with trust domain \"unknown.test\"",
						telemetry.TrustDomainID: "unknown.test",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:       "bundle refresher fails",
			td:         "bad.test",
			expectCode: codes.Internal,
			expectMsg:  "failed to refresh bundle: oh no",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to refresh bundle",
					Data: logrus.Fields{
						telemetry.Error:         "oh no",
						telemetry.TrustDomainID: "bad.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to refresh bundle: oh no",
						telemetry.TrustDomainID: "bad.test",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:       "trust domain malformed with invalid scheme",
			td:         "http://malformed.test",
			expectCode: codes.InvalidArgument,
			expectMsg:  "failed to parse trust domain: scheme is missing or invalid",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse trust domain",
					Data: logrus.Fields{
						telemetry.Error: "scheme is missing or invalid",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "failed to parse trust domain: scheme is missing or invalid",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:       "success with good trust domain",
			td:         "good.test",
			expectCode: codes.OK,
			expectMsg:  "",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Bundle refreshed",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "good.test",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.TrustDomainID: "good.test",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, fakedatastore.New(t))
			defer test.Cleanup()

			_, err := test.client.RefreshBundle(ctx, &trustdomainv1.RefreshBundleRequest{
				TrustDomain: tt.td,
			})
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
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
	br      *fakeBundleRefresher
	logHook *test.Hook
	done    func()
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T, ds datastore.DataStore) *serviceTest {
	br := &fakeBundleRefresher{}
	service := trustdomain.New(trustdomain.Config{
		DataStore:       ds,
		TrustDomain:     td,
		BundleRefresher: br,
	})

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	test := &serviceTest{
		ds:      ds,
		br:      br,
		logHook: logHook,
	}

	overrideContext := func(ctx context.Context) context.Context {
		return rpccontext.WithLogger(ctx, log)
	}

	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		trustdomain.RegisterService(s, service)
	},
		grpctest.OverrideContext(overrideContext),
		grpctest.Middleware(middleware.WithAuditLog(false)),
	)

	conn := server.Dial(t)

	test.client = trustdomainv1.NewTrustDomainClient(conn)
	test.done = server.Stop

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

func (d *fakeDS) CreateFederationRelationship(_ context.Context, fr *datastore.FederationRelationship) (*datastore.FederationRelationship, error) {
	if d.customDSResponse != nil {
		return d.customDSResponse, nil
	}

	return d.DataStore.CreateFederationRelationship(ctx, fr)
}

func (d *fakeDS) UpdateFederationRelationship(_ context.Context, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	if d.customDSResponse != nil {
		return d.customDSResponse, nil
	}

	return d.DataStore.UpdateFederationRelationship(ctx, fr, mask)
}

type fakeBundleRefresher struct {
	reloads int
}

func (r *fakeBundleRefresher) TriggerConfigReload() {
	r.reloads++
}

func (r *fakeBundleRefresher) ReloadCount() int {
	return r.reloads
}

func (r *fakeBundleRefresher) RefreshBundleFor(_ context.Context, td spiffeid.TrustDomain) (bool, error) {
	switch {
	case td == spiffeid.RequireTrustDomainFromString("good.test"):
		return true, nil
	case td == spiffeid.RequireTrustDomainFromString("bad.test"):
		return false, errors.New("oh no")
	default:
		return false, nil
	}
}
