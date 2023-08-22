package delegatedidentity

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	trustDomain1 = spiffeid.RequireTrustDomainFromString("example.org")
	trustDomain2 = spiffeid.RequireTrustDomainFromString("domain.test")
	trustDomain3 = spiffeid.RequireTrustDomainFromString("otherdomain.test")

	id1 = spiffeid.RequireFromPath(trustDomain1, "/one")
	id2 = spiffeid.RequireFromPath(trustDomain1, "/two")

	bundle1 = spiffebundle.FromX509Authorities(trustDomain1, []*x509.Certificate{{Raw: []byte("AAA")}})
	bundle2 = spiffebundle.FromX509Authorities(trustDomain2, []*x509.Certificate{{Raw: []byte("BBB")}})

	jwksBundle1, _ = bundleutil.Marshal(bundle1, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
	jwksBundle2, _ = bundleutil.Marshal(bundle2, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
)

func TestSubscribeToX509SVIDs(t *testing.T) {
	ca := testca.New(t, trustDomain1)

	x509SVID1 := ca.CreateX509SVID(id1)
	x509SVID2 := ca.CreateX509SVID(id2)

	bundle := ca.Bundle()
	federatedBundle1 := testca.New(t, trustDomain2).Bundle()
	federatedBundle2 := testca.New(t, trustDomain3).Bundle()

	identities := []cache.Identity{
		identityFromX509SVID(x509SVID1),
		identityFromX509SVID(x509SVID2),
	}
	identities[1].Entry.Hint = "external"

	for _, tt := range []struct {
		testName      string
		identities    []cache.Identity
		updates       []*cache.WorkloadUpdate
		authSpiffeID  []string
		expectCode    codes.Code
		expectMsg     string
		attestErr     error
		managerErr    error
		expectMetrics []fakemetrics.MetricItem
		expectResp    *delegatedidentityv1.SubscribeToX509SVIDsResponse
	}{
		{
			testName:   "attest error",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Internal,
			expectMsg:  "workload attestation failed",
		},
		{
			testName:     "access to \"privileged\" admin API denied",
			authSpiffeID: []string{"spiffe://example.org/one/wrong"},
			identities: []cache.Identity{
				identities[0],
			},
			expectCode: codes.PermissionDenied,
			expectMsg:  "caller not configured as an authorized delegate",
		},
		{
			testName:     "subscribe to cache changes error",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			managerErr: errors.New("err"),
			expectCode: codes.Unknown,
			expectMsg:  "err",
		},
		{
			testName:     "workload update with one identity",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			updates: []*cache.WorkloadUpdate{
				{Identities: []cache.Identity{
					identities[0],
				},
					Bundle: bundle,
				},
			},
			expectResp: &delegatedidentityv1.SubscribeToX509SVIDsResponse{
				X509Svids: []*delegatedidentityv1.X509SVIDWithKey{
					{
						X509Svid: &types.X509SVID{
							Id:        utilIDProtoFromString(t, x509SVID1.ID.String()),
							CertChain: x509util.RawCertsFromCertificates(x509SVID1.Certificates),
							ExpiresAt: x509SVID1.Certificates[0].NotAfter.Unix(),
						},
						X509SvidKey: pkcs8FromSigner(t, x509SVID1.PrivateKey),
					},
				},
			},
			expectMetrics: generateSubscribeToX509SVIDMetrics(),
		},
		{
			testName:     "workload update with two identities",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			updates: []*cache.WorkloadUpdate{
				{Identities: []cache.Identity{
					identities[0],
					identities[1],
				},
					Bundle: bundle,
				},
			},
			expectResp: &delegatedidentityv1.SubscribeToX509SVIDsResponse{
				X509Svids: []*delegatedidentityv1.X509SVIDWithKey{
					{
						X509Svid: &types.X509SVID{
							Id:        utilIDProtoFromString(t, x509SVID1.ID.String()),
							CertChain: x509util.RawCertsFromCertificates(x509SVID1.Certificates),
							ExpiresAt: x509SVID1.Certificates[0].NotAfter.Unix(),
						},
						X509SvidKey: pkcs8FromSigner(t, x509SVID1.PrivateKey),
					},
					{
						X509Svid: &types.X509SVID{
							Id:        utilIDProtoFromString(t, x509SVID2.ID.String()),
							CertChain: x509util.RawCertsFromCertificates(x509SVID2.Certificates),
							ExpiresAt: x509SVID2.Certificates[0].NotAfter.Unix(),
							Hint:      "external",
						},
						X509SvidKey: pkcs8FromSigner(t, x509SVID2.PrivateKey),
					},
				},
			},
			expectMetrics: generateSubscribeToX509SVIDMetrics(),
		},
		{
			testName:     "no workload update",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			updates:       []*cache.WorkloadUpdate{{}},
			expectResp:    &delegatedidentityv1.SubscribeToX509SVIDsResponse{},
			expectMetrics: generateSubscribeToX509SVIDMetrics(),
		},
		{
			testName:     "workload update without identity.SVID",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			updates: []*cache.WorkloadUpdate{
				{Identities: []cache.Identity{
					identityFromX509SVIDWithoutSVID(x509SVID1),
				}},
			},
			expectCode:    codes.Internal,
			expectMsg:     "could not serialize response",
			expectMetrics: generateSubscribeToX509SVIDMetrics(),
		},
		{
			testName:     "workload update with identity and federated bundles",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identities[0],
					},
					Bundle: bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle1.TrustDomain(): federatedBundle1},
				},
			},
			expectResp: &delegatedidentityv1.SubscribeToX509SVIDsResponse{
				X509Svids: []*delegatedidentityv1.X509SVIDWithKey{
					{
						X509Svid: &types.X509SVID{
							Id:        utilIDProtoFromString(t, x509SVID1.ID.String()),
							CertChain: x509util.RawCertsFromCertificates(x509SVID1.Certificates),
							ExpiresAt: x509SVID1.Certificates[0].NotAfter.Unix(),
						},
						X509SvidKey: pkcs8FromSigner(t, x509SVID1.PrivateKey),
					},
				},
				FederatesWith: []string{federatedBundle1.TrustDomain().IDString()},
			},
			expectMetrics: generateSubscribeToX509SVIDMetrics(),
		},
		{
			testName:     "workload update with identity and two federated bundles",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identities[0],
			},
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identities[0],
					},
					Bundle: bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle1.TrustDomain(): federatedBundle1,
						federatedBundle2.TrustDomain(): federatedBundle2},
				},
			},
			expectResp: &delegatedidentityv1.SubscribeToX509SVIDsResponse{
				X509Svids: []*delegatedidentityv1.X509SVIDWithKey{
					{
						X509Svid: &types.X509SVID{
							Id:        utilIDProtoFromString(t, x509SVID1.ID.String()),
							CertChain: x509util.RawCertsFromCertificates(x509SVID1.Certificates),
							ExpiresAt: x509SVID1.Certificates[0].NotAfter.Unix(),
						},
						X509SvidKey: pkcs8FromSigner(t, x509SVID1.PrivateKey),
					},
				},
				FederatesWith: []string{federatedBundle1.TrustDomain().IDString(),
					federatedBundle2.TrustDomain().IDString()},
			},
			expectMetrics: generateSubscribeToX509SVIDMetrics(),
		},
	} {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			metrics := fakemetrics.New()
			params := testParams{
				CA:           ca,
				Identities:   tt.identities,
				Updates:      tt.updates,
				AuthSpiffeID: tt.authSpiffeID,
				AttestErr:    tt.attestErr,
				ManagerErr:   tt.managerErr,
				Metrics:      metrics,
			}
			runTest(t, params,
				func(ctx context.Context, client delegatedidentityv1.DelegatedIdentityClient) {
					selectors := []*types.Selector{{Type: "sa", Value: "foo"}}
					req := &delegatedidentityv1.SubscribeToX509SVIDsRequest{
						Selectors: selectors,
					}

					stream, err := client.SubscribeToX509SVIDs(ctx, req)

					require.NoError(t, err)
					resp, err := stream.Recv()

					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					spiretest.RequireProtoEqual(t, tt.expectResp, resp)
					require.Equal(t, tt.expectMetrics, metrics.AllMetrics())
				})
		})
	}
}

func TestSubscribeToX509Bundles(t *testing.T) {
	ca := testca.New(t, trustDomain1)

	x509SVID1 := ca.CreateX509SVID(id1)

	for _, tt := range []struct {
		testName     string
		identities   []cache.Identity
		authSpiffeID []string
		expectCode   codes.Code
		expectMsg    string
		attestErr    error
		expectResp   []*delegatedidentityv1.SubscribeToX509BundlesResponse
		cacheUpdates map[spiffeid.TrustDomain]*cache.Bundle
	}{

		{
			testName:   "Attest error",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Internal,
			expectMsg:  "workload attestation failed",
		},
		{
			testName:     "Access to \"privileged\" admin API denied",
			authSpiffeID: []string{"spiffe://example.org/one/wrong"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			expectCode: codes.PermissionDenied,
			expectMsg:  "caller not configured as an authorized delegate",
		},
		{
			testName:     "cache bundle update - one bundle",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			cacheUpdates: map[spiffeid.TrustDomain]*cache.Bundle{
				spiffeid.RequireTrustDomainFromString(bundle1.TrustDomain().IDString()): bundle1,
			},
			expectResp: []*delegatedidentityv1.SubscribeToX509BundlesResponse{
				{
					CaCertificates: map[string][]byte{
						bundle1.TrustDomain().IDString(): marshalBundle(bundle1.X509Authorities()),
					},
				},
			},
		},
		{
			testName:     "cache bundle update - two bundles",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			cacheUpdates: map[spiffeid.TrustDomain]*cache.Bundle{
				spiffeid.RequireTrustDomainFromString(bundle1.TrustDomain().IDString()): bundle1,
				spiffeid.RequireTrustDomainFromString(bundle2.TrustDomain().IDString()): bundle2,
			},
			expectResp: []*delegatedidentityv1.SubscribeToX509BundlesResponse{
				{
					CaCertificates: map[string][]byte{
						bundle1.TrustDomain().IDString(): marshalBundle(bundle1.X509Authorities()),
						bundle2.TrustDomain().IDString(): marshalBundle(bundle2.X509Authorities()),
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			params := testParams{
				CA:           ca,
				Identities:   tt.identities,
				AuthSpiffeID: tt.authSpiffeID,
				AttestErr:    tt.attestErr,
				CacheUpdates: tt.cacheUpdates,
			}
			runTest(t, params,
				func(ctx context.Context, client delegatedidentityv1.DelegatedIdentityClient) {
					req := &delegatedidentityv1.SubscribeToX509BundlesRequest{}

					stream, err := client.SubscribeToX509Bundles(ctx, req)

					require.NoError(t, err)

					for _, multiResp := range tt.expectResp {
						resp, err := stream.Recv()

						spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
						spiretest.RequireProtoEqual(t, multiResp, resp)
					}
				})
		})
	}
}

func TestFetchJWTSVIDs(t *testing.T) {
	ca := testca.New(t, trustDomain1)

	x509SVID1 := ca.CreateX509SVID(id1)
	jwtSVID1Token := ca.CreateJWTSVID(id1, []string{"AUDIENCE"}).Marshal()
	x509SVID2 := ca.CreateX509SVID(id2)
	jwtSVID2Token := ca.CreateJWTSVID(id2, []string{"AUDIENCE"}).Marshal()

	identities := []cache.Identity{
		identityFromX509SVID(x509SVID1),
		identityFromX509SVID(x509SVID2),
	}

	identities[0].Entry.Hint = "internal"

	for _, tt := range []struct {
		testName     string
		identities   []cache.Identity
		jwtSVIDsResp map[spiffeid.ID]*client.JWTSVID
		authSpiffeID []string
		audience     []string
		selectors    []*types.Selector
		expectCode   codes.Code
		expectMsg    string
		attestErr    error
		managerErr   error
		expectResp   *delegatedidentityv1.FetchJWTSVIDsResponse
	}{
		{
			testName:   "missing required audience",
			expectCode: codes.InvalidArgument,
			expectMsg:  "audience must be specified",
		},
		{
			testName:   "Attest error",
			attestErr:  errors.New("ohno"),
			audience:   []string{"AUDIENCE"},
			expectCode: codes.Internal,
			expectMsg:  "workload attestation failed",
		},
		{
			testName:     "Access to \"privileged\" admin API denied",
			authSpiffeID: []string{"spiffe://example.org/one/wrong"},
			audience:     []string{"AUDIENCE"},
			identities: []cache.Identity{
				identities[0],
			},
			expectCode: codes.PermissionDenied,
			expectMsg:  "caller not configured as an authorized delegate",
		},
		{
			testName:     "fetch error",
			authSpiffeID: []string{"spiffe://example.org/one"},
			selectors:    []*types.Selector{{Type: "sa", Value: "foo"}},
			audience:     []string{"AUDIENCE"},
			identities: []cache.Identity{
				identities[0],
			},
			managerErr: errors.New("ohno"),
			expectCode: codes.Unavailable,
			expectMsg:  "could not fetch JWT-SVID: ohno",
		},
		{
			testName:     "selectors missing type",
			authSpiffeID: []string{"spiffe://example.org/one"},
			selectors:    []*types.Selector{{Type: "", Value: "foo"}},
			audience:     []string{"AUDIENCE"},
			identities: []cache.Identity{
				identities[0],
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse provided selectors",
		},
		{
			testName:     "selectors missing value",
			authSpiffeID: []string{"spiffe://example.org/one"},
			selectors:    []*types.Selector{{Type: "sa", Value: ""}},
			audience:     []string{"AUDIENCE"},
			identities: []cache.Identity{
				identities[0],
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse provided selectors",
		},
		{
			testName:     "selectors type contains ':'",
			authSpiffeID: []string{"spiffe://example.org/one"},
			selectors:    []*types.Selector{{Type: "sa:bar", Value: "boo"}},
			audience:     []string{"AUDIENCE"},
			identities: []cache.Identity{
				identities[0],
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "could not parse provided selectors",
		},
		{
			testName:     "success with one identity",
			authSpiffeID: []string{"spiffe://example.org/one"},
			selectors:    []*types.Selector{{Type: "sa", Value: "foo"}},
			audience:     []string{"AUDIENCE"},
			identities: []cache.Identity{
				identities[0],
			},
			jwtSVIDsResp: map[spiffeid.ID]*client.JWTSVID{
				id1: {
					Token:     jwtSVID1Token,
					ExpiresAt: time.Unix(1680786600, 0),
					IssuedAt:  time.Unix(1680783000, 0),
				},
			},
			expectResp: &delegatedidentityv1.FetchJWTSVIDsResponse{
				Svids: []*types.JWTSVID{
					{
						Token:     jwtSVID1Token,
						Id:        api.ProtoFromID(id1),
						Hint:      "internal",
						ExpiresAt: 1680786600,
						IssuedAt:  1680783000,
					},
				},
			},
		},
		{
			testName:     "success with two identities",
			authSpiffeID: []string{"spiffe://example.org/one"},
			selectors:    []*types.Selector{{Type: "sa", Value: "foo"}},
			audience:     []string{"AUDIENCE"},
			identities:   identities,
			jwtSVIDsResp: map[spiffeid.ID]*client.JWTSVID{
				id1: {
					Token:     jwtSVID1Token,
					ExpiresAt: time.Unix(1680786600, 0),
					IssuedAt:  time.Unix(1680783000, 0),
				},
				id2: {
					Token:     jwtSVID2Token,
					ExpiresAt: time.Unix(1680786600, 0),
					IssuedAt:  time.Unix(1680783000, 0),
				},
			},
			expectResp: &delegatedidentityv1.FetchJWTSVIDsResponse{
				Svids: []*types.JWTSVID{
					{
						Token:     jwtSVID1Token,
						Id:        api.ProtoFromID(id1),
						Hint:      "internal",
						ExpiresAt: 1680786600,
						IssuedAt:  1680783000,
					},
					{
						Token:     jwtSVID2Token,
						Id:        api.ProtoFromID(id2),
						Hint:      "",
						ExpiresAt: 1680786600,
						IssuedAt:  1680783000,
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			params := testParams{
				CA:           ca,
				Identities:   tt.identities,
				AuthSpiffeID: tt.authSpiffeID,
				AttestErr:    tt.attestErr,
				ManagerErr:   tt.managerErr,
				JwtSVIDS:     tt.jwtSVIDsResp,
			}
			runTest(t, params,
				func(ctx context.Context, client delegatedidentityv1.DelegatedIdentityClient) {
					resp, err := client.FetchJWTSVIDs(ctx, &delegatedidentityv1.FetchJWTSVIDsRequest{
						Audience:  tt.audience,
						Selectors: tt.selectors,
					})

					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					if tt.expectCode != codes.OK {
						assert.Nil(t, resp)
						return
					}
					for _, svid := range resp.Svids {
						_, err := jwtsvid.ParseInsecure(svid.Token, tt.audience)
						require.NoError(t, err, "JWT-SVID token is malformed")
					}
					spiretest.AssertProtoEqual(t, tt.expectResp, resp)
				})
		})
	}
}
func TestSubscribeToJWTBundles(t *testing.T) {
	ca := testca.New(t, trustDomain1)

	x509SVID1 := ca.CreateX509SVID(id1)

	for _, tt := range []struct {
		testName     string
		identities   []cache.Identity
		authSpiffeID []string
		expectCode   codes.Code
		expectMsg    string
		attestErr    error
		expectResp   []*delegatedidentityv1.SubscribeToJWTBundlesResponse
		cacheUpdates map[spiffeid.TrustDomain]*cache.Bundle
	}{

		{
			testName:   "Attest error",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Internal,
			expectMsg:  "workload attestation failed",
		},
		{
			testName:     "Access to \"privileged\" admin API denied",
			authSpiffeID: []string{"spiffe://example.org/one/wrong"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			expectCode: codes.PermissionDenied,
			expectMsg:  "caller not configured as an authorized delegate",
		},
		{
			testName:     "cache bundle update - one bundle",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			cacheUpdates: map[spiffeid.TrustDomain]*cache.Bundle{
				spiffeid.RequireTrustDomainFromString(bundle1.TrustDomain().IDString()): bundle1,
			},
			expectResp: []*delegatedidentityv1.SubscribeToJWTBundlesResponse{
				{
					Bundles: map[string][]byte{
						bundle1.TrustDomain().IDString(): jwksBundle1,
					},
				},
			},
		},
		{
			testName:     "cache bundle update - two bundles",
			authSpiffeID: []string{"spiffe://example.org/one"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			cacheUpdates: map[spiffeid.TrustDomain]*cache.Bundle{
				spiffeid.RequireTrustDomainFromString(bundle1.TrustDomain().IDString()): bundle1,
				spiffeid.RequireTrustDomainFromString(bundle2.TrustDomain().IDString()): bundle2,
			},
			expectResp: []*delegatedidentityv1.SubscribeToJWTBundlesResponse{
				{
					Bundles: map[string][]byte{
						bundle1.TrustDomain().IDString(): jwksBundle1,
						bundle2.TrustDomain().IDString(): jwksBundle2,
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			params := testParams{
				CA:           ca,
				Identities:   tt.identities,
				AuthSpiffeID: tt.authSpiffeID,
				AttestErr:    tt.attestErr,
				CacheUpdates: tt.cacheUpdates,
			}
			runTest(t, params,
				func(ctx context.Context, client delegatedidentityv1.DelegatedIdentityClient) {
					req := &delegatedidentityv1.SubscribeToJWTBundlesRequest{}

					stream, err := client.SubscribeToJWTBundles(ctx, req)

					require.NoError(t, err)

					for _, multiResp := range tt.expectResp {
						resp, err := stream.Recv()

						spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
						spiretest.RequireProtoEqual(t, multiResp, resp)
					}
				})
		})
	}
}

type testParams struct {
	CA           *testca.CA
	Identities   []cache.Identity
	Updates      []*cache.WorkloadUpdate
	CacheUpdates map[spiffeid.TrustDomain]*cache.Bundle
	JwtSVIDS     map[spiffeid.ID]*client.JWTSVID
	AuthSpiffeID []string
	AttestErr    error
	ManagerErr   error
	Metrics      *fakemetrics.FakeMetrics
}

func runTest(t *testing.T, params testParams, fn func(ctx context.Context, client delegatedidentityv1.DelegatedIdentityClient)) {
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	manager := &FakeManager{
		Manager:     nil,
		ca:          params.CA,
		identities:  params.Identities,
		updates:     params.Updates,
		cacheUpdate: params.CacheUpdates,
		jwtSVIDs:    params.JwtSVIDS,
		err:         params.ManagerErr,
	}

	service := New(Config{
		Log:                 log,
		Manager:             manager,
		Metrics:             params.Metrics,
		AuthorizedDelegates: params.AuthSpiffeID,
	})

	service.attestor = FakeAttestor{
		err: params.AttestErr,
	}

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.WithLogger(log))
	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)

	delegatedidentityv1.RegisterDelegatedIdentityServer(server, service)
	addr := spiretest.ServeGRPCServerOnTempUDSSocket(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, _ := grpc.DialContext(ctx, "unix:"+addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { conn.Close() })

	fn(ctx, delegatedidentityv1.NewDelegatedIdentityClient(conn))
	cancel()
	server.GracefulStop()
}

type FakeAttestor struct {
	selectors []*common.Selector
	err       error
}

func (fa FakeAttestor) Attest(context.Context) ([]*common.Selector, error) {
	return fa.selectors, fa.err
}

type FakeManager struct {
	manager.Manager

	ca          *testca.CA
	identities  []cache.Identity
	jwtSVIDs    map[spiffeid.ID]*client.JWTSVID
	updates     []*cache.WorkloadUpdate
	cacheUpdate map[spiffeid.TrustDomain]*cache.Bundle

	subscribers int32
	err         error
}

func (m *FakeManager) Subscribers() int {
	return int(atomic.LoadInt32(&m.subscribers))
}

func (m *FakeManager) subscriberDone() {
	atomic.AddInt32(&m.subscribers, -1)
}

func (m *FakeManager) SubscribeToCacheChanges(context.Context, cache.Selectors) (cache.Subscriber, error) {
	if m.err != nil {
		return nil, m.err
	}
	atomic.AddInt32(&m.subscribers, 1)
	return newFakeSubscriber(m, m.updates), nil
}

func (m *FakeManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	if m.err != nil {
		return nil, m.err
	}

	spiffeID, err := spiffeid.FromString(entry.SpiffeId)
	if err != nil {
		return nil, err
	}

	svid, ok := m.jwtSVIDs[spiffeID]
	if !ok {
		return nil, errors.New("not found")
	}
	return svid, nil
}

func (m *FakeManager) MatchingRegistrationEntries([]*common.Selector) []*common.RegistrationEntry {
	out := make([]*common.RegistrationEntry, 0, len(m.identities))
	for _, identity := range m.identities {
		out = append(out, identity.Entry)
	}
	return out
}

type fakeSubscriber struct {
	m      *FakeManager
	ch     chan *cache.WorkloadUpdate
	cancel context.CancelFunc
}

func newFakeSubscriber(m *FakeManager, updates []*cache.WorkloadUpdate) *fakeSubscriber {
	ch := make(chan *cache.WorkloadUpdate)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for _, update := range updates {
			select {
			case ch <- update:
			case <-ctx.Done():
				return
			}
		}
		<-ctx.Done()
	}()
	return &fakeSubscriber{
		m:      m,
		ch:     ch,
		cancel: cancel,
	}
}

func (s *fakeSubscriber) Updates() <-chan *cache.WorkloadUpdate {
	return s.ch
}

func (s *fakeSubscriber) Finish() {
	s.cancel()
	s.m.subscriberDone()
}

func identityFromX509SVID(svid *x509svid.SVID) cache.Identity {
	return cache.Identity{
		Entry:      &common.RegistrationEntry{SpiffeId: svid.ID.String()},
		PrivateKey: svid.PrivateKey,
		SVID:       svid.Certificates,
	}
}

func identityFromX509SVIDWithoutSVID(svid *x509svid.SVID) cache.Identity {
	return cache.Identity{
		Entry:      &common.RegistrationEntry{SpiffeId: svid.ID.String()},
		PrivateKey: svid.PrivateKey,
		SVID:       nil,
	}
}

func pkcs8FromSigner(t *testing.T, key crypto.Signer) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return keyBytes
}

func utilIDProtoFromString(t *testing.T, id string) *types.SPIFFEID {
	spiffeID, err := idutil.IDProtoFromString(id)
	require.NoError(t, err)
	return spiffeID
}

func (m *FakeManager) SubscribeToBundleChanges() *cache.BundleStream {
	myCache := newTestCache()
	myCache.BundleCache.Update(m.cacheUpdate)

	return myCache.BundleCache.SubscribeToBundleChanges()
}

func newTestCache() *cache.Cache {
	log, _ := test.NewNullLogger()
	return cache.New(log, trustDomain1, bundle1, telemetry.Blackhole{})
}

func generateSubscribeToX509SVIDMetrics() []fakemetrics.MetricItem {
	return []fakemetrics.MetricItem{
		{
			Type:   fakemetrics.MeasureSinceWithLabelsType,
			Key:    []string{telemetry.DelegatedIdentityAPI, telemetry.SubscribeX509SVIDs, telemetry.FirstUpdate, telemetry.ElapsedTime},
			Val:    0,
			Labels: []telemetry.Label{},
		},
	}
}
