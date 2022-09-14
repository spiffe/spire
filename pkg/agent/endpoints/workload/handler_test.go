package workload_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	workloadPB "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	td  = spiffeid.RequireTrustDomainFromString("domain.test")
	td2 = spiffeid.RequireTrustDomainFromString("domain2.test")

	workloadID = spiffeid.RequireFromPath(td, "/workload")
)

func TestFetchX509SVID(t *testing.T) {
	ca := testca.New(t, td)

	x509SVID1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	x509SVID2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/two"))
	bundle := ca.Bundle()
	federatedBundle := testca.New(t, td2).Bundle()

	for _, tt := range []struct {
		name       string
		updates    []*cache.WorkloadUpdate
		attestErr  error
		managerErr error
		asPID      int
		expectCode codes.Code
		expectMsg  string
		expectResp *workloadPB.X509SVIDResponse
		expectLogs []spiretest.LogEntry
	}{
		{
			name:       "no identity issued",
			updates:    []*cache.WorkloadUpdate{{}},
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No identity issued",
					Data: logrus.Fields{
						"registered": "false",
						"service":    "WorkloadAPI",
						"method":     "FetchX509SVID",
					},
				},
			},
		},
		{
			name:       "no identity issued (healthcheck)",
			updates:    []*cache.WorkloadUpdate{{}},
			asPID:      os.Getpid(),
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
		},
		{
			name:       "attest error",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Unknown,
			expectMsg:  "ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Workload attestation failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchX509SVID",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name:       "subscribe to cache changes error",
			managerErr: errors.New("err"),
			expectCode: codes.Unknown,
			expectMsg:  "err",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Subscribe to cache changes failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchX509SVID",
						logrus.ErrorKey: "err",
					},
				},
			},
		},
		{
			name: "with identity and federated bundles",
			updates: []*cache.WorkloadUpdate{{
				Identities: []cache.Identity{
					identityFromX509SVID(x509SVID1),
				},
				Bundle: utilBundleFromBundle(t, bundle),
				FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
					federatedBundle.TrustDomain(): utilBundleFromBundle(t, federatedBundle),
				},
			}},
			expectCode: codes.OK,
			expectResp: &workloadPB.X509SVIDResponse{
				Svids: []*workloadPB.X509SVID{
					{
						SpiffeId:    x509SVID1.ID.String(),
						X509Svid:    x509util.DERFromCertificates(x509SVID1.Certificates),
						X509SvidKey: pkcs8FromSigner(t, x509SVID1.PrivateKey),
						Bundle:      x509util.DERFromCertificates(bundle.X509Authorities()),
					},
				},
				FederatedBundles: map[string][]byte{
					federatedBundle.TrustDomain().IDString(): x509util.DERFromCertificates(federatedBundle.X509Authorities()),
				},
			},
		},
		{
			name: "with two identities",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identityFromX509SVID(x509SVID1),
						identityFromX509SVID(x509SVID2),
					},
					Bundle: utilBundleFromBundle(t, bundle),
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.X509SVIDResponse{
				Svids: []*workloadPB.X509SVID{
					{
						SpiffeId:    x509SVID1.ID.String(),
						X509Svid:    x509util.DERFromCertificates(x509SVID1.Certificates),
						X509SvidKey: pkcs8FromSigner(t, x509SVID1.PrivateKey),
						Bundle:      x509util.DERFromCertificates(bundle.X509Authorities()),
					},
					{
						SpiffeId:    x509SVID2.ID.String(),
						X509Svid:    x509util.DERFromCertificates(x509SVID2.Certificates),
						X509SvidKey: pkcs8FromSigner(t, x509SVID2.PrivateKey),
						Bundle:      x509util.DERFromCertificates(bundle.X509Authorities()),
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			params := testParams{
				CA:         ca,
				Updates:    tt.updates,
				AttestErr:  tt.attestErr,
				ExpectLogs: tt.expectLogs,
				AsPID:      tt.asPID,
				ManagerErr: tt.managerErr,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					stream, err := client.FetchX509SVID(ctx, &workloadPB.X509SVIDRequest{})
					require.NoError(t, err)

					resp, err := stream.Recv()
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					spiretest.RequireProtoEqual(t, tt.expectResp, resp)
				})
		})
	}
}

func TestFetchX509Bundles(t *testing.T) {
	ca := testca.New(t, td)
	x509SVID := ca.CreateX509SVID(workloadID)

	bundle := ca.Bundle()
	bundleX509 := x509util.DERFromCertificates(bundle.X509Authorities())

	federatedBundle := testca.New(t, td2).Bundle()
	federatedBundleX509 := x509util.DERFromCertificates(federatedBundle.X509Authorities())

	for _, tt := range []struct {
		testName                      string
		updates                       []*cache.WorkloadUpdate
		attestErr                     error
		managerErr                    error
		expectCode                    codes.Code
		expectMsg                     string
		expectResp                    *workloadPB.X509BundlesResponse
		expectLogs                    []spiretest.LogEntry
		allowUnauthenticatedVerifiers bool
	}{
		{
			testName:   "no identity issued",
			updates:    []*cache.WorkloadUpdate{{}},
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No identity issued",
					Data: logrus.Fields{
						"registered": "false",
						"service":    "WorkloadAPI",
						"method":     "FetchX509Bundles",
					},
				},
			},
		},
		{
			testName:   "attest error",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Unknown,
			expectMsg:  "ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Workload attestation failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchX509Bundles",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			testName:   "subscribe to cache changes error",
			managerErr: errors.New("err"),
			expectCode: codes.Unknown,
			expectMsg:  "err",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Subscribe to cache changes failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchX509Bundles",
						logrus.ErrorKey: "err",
					},
				},
			},
		},
		{
			testName: "cache update unexpectedly missing bundle",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identityFromX509SVID(x509SVID),
					},
				},
			},
			expectCode: codes.Unavailable,
			expectMsg:  "could not serialize response: bundle not available",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Could not serialize X509 bundle response",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchX509Bundles",
						logrus.ErrorKey: "bundle not available",
					},
				},
			},
		},
		{
			testName: "success",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identityFromX509SVID(x509SVID),
					},
					Bundle: utilBundleFromBundle(t, bundle),
					FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
						federatedBundle.TrustDomain(): utilBundleFromBundle(t, federatedBundle),
					},
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.X509BundlesResponse{
				Bundles: map[string][]byte{
					bundle.TrustDomain().IDString():          bundleX509,
					federatedBundle.TrustDomain().IDString(): federatedBundleX509,
				},
			},
		},
		{
			testName:                      "when allowed to fetch without identity",
			allowUnauthenticatedVerifiers: true,
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{},
					Bundle:     utilBundleFromBundle(t, bundle),
					FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
						federatedBundle.TrustDomain(): utilBundleFromBundle(t, federatedBundle),
					},
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.X509BundlesResponse{
				Bundles: map[string][]byte{
					bundle.TrustDomain().IDString(): bundleX509,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			params := testParams{
				CA:                            ca,
				Updates:                       tt.updates,
				AttestErr:                     tt.attestErr,
				ExpectLogs:                    tt.expectLogs,
				AllowUnauthenticatedVerifiers: tt.allowUnauthenticatedVerifiers,
				ManagerErr:                    tt.managerErr,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					stream, err := client.FetchX509Bundles(ctx, &workloadPB.X509BundlesRequest{})
					require.NoError(t, err)

					resp, err := stream.Recv()
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					spiretest.RequireProtoEqual(t, tt.expectResp, resp)
				})
		})
	}
}

func TestFetchX509Bundles_MultipleUpdates(t *testing.T) {
	ca := testca.New(t, td)
	x509SVID := ca.CreateX509SVID(workloadID)

	bundle := ca.Bundle()
	bundleX509 := x509util.DERFromCertificates(bundle.X509Authorities())

	otherBundle := testca.New(t, td).Bundle()
	otherBundleX509 := x509util.DERFromCertificates(otherBundle.X509Authorities())

	updates := []*cache.WorkloadUpdate{
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, bundle),
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, otherBundle),
		},
	}

	expectResp := []*workloadPB.X509BundlesResponse{
		{
			Bundles: map[string][]byte{
				bundle.TrustDomain().IDString(): bundleX509,
			},
		},
		{
			Bundles: map[string][]byte{
				bundle.TrustDomain().IDString(): otherBundleX509,
			},
		},
	}

	params := testParams{
		CA:                            ca,
		Updates:                       updates,
		AttestErr:                     nil,
		ExpectLogs:                    nil,
		AllowUnauthenticatedVerifiers: false,
	}

	runTest(t, params,
		func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
			stream, err := client.FetchX509Bundles(ctx, &workloadPB.X509BundlesRequest{})
			require.NoError(t, err)

			resp, err := stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[0], resp)

			resp, err = stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[1], resp)
		})
}

func TestFetchX509Bundles_SpuriousUpdates(t *testing.T) {
	ca := testca.New(t, td)
	x509SVID := ca.CreateX509SVID(workloadID)

	bundle := ca.Bundle()
	bundleX509 := x509util.DERFromCertificates(bundle.X509Authorities())

	otherBundle := testca.New(t, td).Bundle()
	otherBundleX509 := x509util.DERFromCertificates(otherBundle.X509Authorities())

	updates := []*cache.WorkloadUpdate{
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, bundle),
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, bundle),
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, otherBundle),
		},
	}

	expectResp := []*workloadPB.X509BundlesResponse{
		{
			Bundles: map[string][]byte{
				bundle.TrustDomain().IDString(): bundleX509,
			},
		},
		{
			Bundles: map[string][]byte{
				bundle.TrustDomain().IDString(): otherBundleX509,
			},
		},
	}

	params := testParams{
		CA:                            ca,
		Updates:                       updates,
		AttestErr:                     nil,
		ExpectLogs:                    nil,
		AllowUnauthenticatedVerifiers: false,
	}

	runTest(t, params,
		func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
			stream, err := client.FetchX509Bundles(ctx, &workloadPB.X509BundlesRequest{})
			require.NoError(t, err)

			// First response should be the original update.
			resp, err := stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[0], resp)

			// Next response should be the third update, as the second contained
			// no bundle changes and should have been skipped.
			resp, err = stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[1], resp)
		})
}

func TestFetchJWTSVID(t *testing.T) {
	ca := testca.New(t, td)

	x509SVID1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	x509SVID2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/two"))

	for _, tt := range []struct {
		name           string
		identities     []cache.Identity
		spiffeID       string
		audience       []string
		attestErr      error
		managerErr     error
		expectCode     codes.Code
		expectMsg      string
		expectTokenIDs []spiffeid.ID
		expectLogs     []spiretest.LogEntry
	}{
		{
			name:       "missing required audience",
			expectCode: codes.InvalidArgument,
			expectMsg:  "audience must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required audience parameter",
					Data: logrus.Fields{
						"service": "WorkloadAPI",
						"method":  "FetchJWTSVID",
					},
				},
			},
		},
		{
			name:       "spiffe_id set, but not a valid SPIFFE ID",
			audience:   []string{"AUDIENCE"},
			spiffeID:   "foo",
			expectCode: codes.InvalidArgument,
			expectMsg:  "invalid requested SPIFFE ID: scheme is missing or invalid",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid requested SPIFFE ID",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchJWTSVID",
						"spiffe_id":     "foo",
						logrus.ErrorKey: "scheme is missing or invalid",
					},
				},
			},
		},
		{
			name:       "no identity issued",
			audience:   []string{"AUDIENCE"},
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No identity issued",
					Data: logrus.Fields{
						"registered": "false",
						"service":    "WorkloadAPI",
						"method":     "FetchJWTSVID",
					},
				},
			},
		},
		{
			name: "identity found but unexpected SPIFFE ID",
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
				identityFromX509SVID(x509SVID2),
			},
			spiffeID:   spiffeid.RequireFromPath(td, "/unexpected").String(),
			audience:   []string{"AUDIENCE"},
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No identity issued",
					Data: logrus.Fields{
						"registered": "false",
						"service":    "WorkloadAPI",
						"method":     "FetchJWTSVID",
					},
				},
			},
		},
		{
			name:       "attest error",
			audience:   []string{"AUDIENCE"},
			attestErr:  errors.New("ohno"),
			expectCode: codes.Unknown,
			expectMsg:  "ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Workload attestation failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchJWTSVID",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name:     "fetch error",
			audience: []string{"AUDIENCE"},
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
			},
			managerErr: errors.New("ohno"),
			expectCode: codes.Unavailable,
			expectMsg:  "could not fetch JWT-SVID: ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Could not fetch JWT-SVID",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"spiffe_id":     "spiffe://domain.test/one",
						"method":        "FetchJWTSVID",
						"registered":    "true",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name: "success all",
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
				identityFromX509SVID(x509SVID2),
			},
			audience:       []string{"AUDIENCE"},
			expectCode:     codes.OK,
			expectTokenIDs: []spiffeid.ID{x509SVID1.ID, x509SVID2.ID},
		},
		{
			name: "success specific",
			identities: []cache.Identity{
				identityFromX509SVID(x509SVID1),
				identityFromX509SVID(x509SVID2),
			},
			spiffeID:       x509SVID2.ID.String(),
			audience:       []string{"AUDIENCE"},
			expectCode:     codes.OK,
			expectTokenIDs: []spiffeid.ID{x509SVID2.ID},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			params := testParams{
				CA:         ca,
				Identities: tt.identities,
				AttestErr:  tt.attestErr,
				ManagerErr: tt.managerErr,
				ExpectLogs: tt.expectLogs,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					resp, err := client.FetchJWTSVID(ctx, &workloadPB.JWTSVIDRequest{
						SpiffeId: tt.spiffeID,
						Audience: tt.audience,
					})
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)

					if tt.expectCode != codes.OK {
						assert.Nil(t, resp)
						return
					}
					var tokenIDs []spiffeid.ID
					for _, svid := range resp.Svids {
						parsedSVID, err := jwtsvid.ParseInsecure(svid.Svid, tt.audience)
						require.NoError(t, err, "JWT-SVID token is malformed")
						tokenIDs = append(tokenIDs, parsedSVID.ID)
					}
					assert.Equal(t, tt.expectTokenIDs, tokenIDs)
				})
		})
	}
}

func TestFetchJWTBundles(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)

	x509SVID := ca.CreateX509SVID(workloadID)

	indent := func(in []byte) []byte {
		buf := new(bytes.Buffer)
		require.NoError(t, json.Indent(buf, in, "", "    "))
		return buf.Bytes()
	}

	bundle := ca.Bundle()
	bundleJWKS, err := bundle.JWTBundle().Marshal()
	require.NoError(t, err)
	bundleJWKS = indent(bundleJWKS)

	federatedBundle := testca.New(t, spiffeid.RequireTrustDomainFromString("domain2.test")).Bundle()
	federatedBundleJWKS, err := federatedBundle.JWTBundle().Marshal()
	require.NoError(t, err)
	federatedBundleJWKS = indent(federatedBundleJWKS)

	for _, tt := range []struct {
		name                          string
		updates                       []*cache.WorkloadUpdate
		attestErr                     error
		managerErr                    error
		expectCode                    codes.Code
		expectMsg                     string
		expectResp                    *workloadPB.JWTBundlesResponse
		expectLogs                    []spiretest.LogEntry
		allowUnauthenticatedVerifiers bool
	}{
		{
			name:       "no identity issued",
			updates:    []*cache.WorkloadUpdate{{}},
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No identity issued",
					Data: logrus.Fields{
						"registered": "false",
						"service":    "WorkloadAPI",
						"method":     "FetchJWTBundles",
					},
				},
			},
		},
		{
			name:       "attest error",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Unknown,
			expectMsg:  "ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Workload attestation failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchJWTBundles",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name:       "subscribe to cache changes error",
			managerErr: errors.New("err"),
			expectCode: codes.Unknown,
			expectMsg:  "err",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Subscribe to cache changes failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchJWTBundles",
						logrus.ErrorKey: "err",
					},
				},
			},
		},
		{
			name: "cache update unexpectedly missing bundle",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identityFromX509SVID(x509SVID),
					},
				},
			},
			expectCode: codes.Unavailable,
			expectMsg:  "could not serialize response: bundle not available",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Could not serialize JWT bundle response",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "FetchJWTBundles",
						logrus.ErrorKey: "bundle not available",
					},
				},
			},
		},
		{
			name: "success",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identityFromX509SVID(x509SVID),
					},
					Bundle: utilBundleFromBundle(t, bundle),
					FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
						federatedBundle.TrustDomain(): utilBundleFromBundle(t, federatedBundle),
					},
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.JWTBundlesResponse{
				Bundles: map[string][]byte{
					bundle.TrustDomain().IDString():          bundleJWKS,
					federatedBundle.TrustDomain().IDString(): federatedBundleJWKS,
				},
			},
		},
		{
			name:                          "when allowed to fetch without identity",
			allowUnauthenticatedVerifiers: true,
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{},
					Bundle:     utilBundleFromBundle(t, bundle),
					FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
						federatedBundle.TrustDomain(): utilBundleFromBundle(t, federatedBundle),
					},
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.JWTBundlesResponse{
				Bundles: map[string][]byte{
					bundle.TrustDomain().IDString(): bundleJWKS,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			params := testParams{
				CA:                            ca,
				Updates:                       tt.updates,
				AttestErr:                     tt.attestErr,
				ExpectLogs:                    tt.expectLogs,
				AllowUnauthenticatedVerifiers: tt.allowUnauthenticatedVerifiers,
				ManagerErr:                    tt.managerErr,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					stream, err := client.FetchJWTBundles(ctx, &workloadPB.JWTBundlesRequest{})
					require.NoError(t, err)

					resp, err := stream.Recv()
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					spiretest.RequireProtoEqual(t, tt.expectResp, resp)
				})
		})
	}
}

func TestFetchJWTBundles_MultipleUpdates(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)

	x509SVID := ca.CreateX509SVID(workloadID)

	indent := func(in []byte) []byte {
		buf := new(bytes.Buffer)
		require.NoError(t, json.Indent(buf, in, "", "    "))
		return buf.Bytes()
	}

	bundle := ca.Bundle()
	bundleJWKS, err := bundle.JWTBundle().Marshal()
	require.NoError(t, err)
	bundleJWKS = indent(bundleJWKS)

	otherBundle := testca.New(t, spiffeid.RequireTrustDomainFromString("domain2.test")).Bundle()
	otherBundleJWKS, err := otherBundle.JWTBundle().Marshal()
	require.NoError(t, err)
	otherBundleJWKS = indent(otherBundleJWKS)

	updates := []*cache.WorkloadUpdate{
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, bundle),
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, otherBundle),
		},
	}

	expectResp := []*workloadPB.JWTBundlesResponse{
		{
			Bundles: map[string][]byte{
				bundle.TrustDomain().IDString(): bundleJWKS,
			},
		},
		{
			Bundles: map[string][]byte{
				otherBundle.TrustDomain().IDString(): otherBundleJWKS,
			},
		},
	}

	params := testParams{
		CA:                            ca,
		Updates:                       updates,
		AttestErr:                     nil,
		ExpectLogs:                    nil,
		AllowUnauthenticatedVerifiers: false,
	}

	runTest(t, params,
		func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
			stream, err := client.FetchJWTBundles(ctx, &workloadPB.JWTBundlesRequest{})
			require.NoError(t, err)

			resp, err := stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[0], resp)

			resp, err = stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[1], resp)
		})
}

func TestFetchJWTBundles_SpuriousUpdates(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := testca.New(t, td)

	x509SVID := ca.CreateX509SVID(workloadID)

	indent := func(in []byte) []byte {
		buf := new(bytes.Buffer)
		require.NoError(t, json.Indent(buf, in, "", "    "))
		return buf.Bytes()
	}

	bundle := ca.Bundle()
	bundleJWKS, err := bundle.JWTBundle().Marshal()
	require.NoError(t, err)
	bundleJWKS = indent(bundleJWKS)

	otherBundle := testca.New(t, spiffeid.RequireTrustDomainFromString("domain2.test")).Bundle()
	otherBundleJWKS, err := otherBundle.JWTBundle().Marshal()
	require.NoError(t, err)
	otherBundleJWKS = indent(otherBundleJWKS)

	updates := []*cache.WorkloadUpdate{
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, bundle),
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, bundle),
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID),
			},
			Bundle: utilBundleFromBundle(t, otherBundle),
		},
	}

	expectResp := []*workloadPB.JWTBundlesResponse{
		{
			Bundles: map[string][]byte{
				bundle.TrustDomain().IDString(): bundleJWKS,
			},
		},
		{
			Bundles: map[string][]byte{
				otherBundle.TrustDomain().IDString(): otherBundleJWKS,
			},
		},
	}

	params := testParams{
		CA:                            ca,
		Updates:                       updates,
		AttestErr:                     nil,
		ExpectLogs:                    nil,
		AllowUnauthenticatedVerifiers: false,
	}

	runTest(t, params,
		func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
			stream, err := client.FetchJWTBundles(ctx, &workloadPB.JWTBundlesRequest{})
			require.NoError(t, err)

			// First response should be the original update.
			resp, err := stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[0], resp)

			// Next response should be the third update, as the second contained
			// no bundle changes and should have been skipped.
			resp, err = stream.Recv()
			spiretest.RequireGRPCStatus(t, err, codes.OK, "")
			spiretest.RequireProtoEqual(t, expectResp[1], resp)
		})
}

func TestValidateJWTSVID(t *testing.T) {
	ca := testca.New(t, td)
	ca2 := testca.New(t, td2)

	bundle := ca.Bundle()
	federatedBundle := ca2.Bundle()

	svid := ca.CreateJWTSVID(workloadID, []string{"AUDIENCE"})
	federatedSVID := ca2.CreateJWTSVID(spiffeid.RequireFromPath(td2, "/federated-workload"), []string{"AUDIENCE"})

	updatesWithBundleOnly := []*cache.WorkloadUpdate{{
		Bundle: utilBundleFromBundle(t, bundle),
	}}

	updatesWithFederatedBundle := []*cache.WorkloadUpdate{{
		Bundle: utilBundleFromBundle(t, bundle),
		FederatedBundles: map[spiffeid.TrustDomain]*bundleutil.Bundle{
			federatedBundle.TrustDomain(): utilBundleFromBundle(t, federatedBundle),
		},
	}}

	for _, tt := range []struct {
		name                    string
		svid                    string
		audience                string
		updates                 []*cache.WorkloadUpdate
		attestErr               error
		expectCode              codes.Code
		expectMsg               string
		expectLogs              []spiretest.LogEntry
		expectResponse          *workloadPB.ValidateJWTSVIDResponse
		allowedForeignJWTClaims map[string]struct{}
	}{
		{
			name:       "missing required audience",
			expectCode: codes.InvalidArgument,
			expectMsg:  "audience must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required audience parameter",
					Data: logrus.Fields{
						"service": "WorkloadAPI",
						"method":  "ValidateJWTSVID",
					},
				},
			},
		},
		{
			name:       "missing required svid",
			audience:   "AUDIENCE",
			expectCode: codes.InvalidArgument,
			expectMsg:  "svid must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required svid parameter",
					Data: logrus.Fields{
						"service": "WorkloadAPI",
						"method":  "ValidateJWTSVID",
					},
				},
			},
		},
		{
			name:       "malformed svid",
			svid:       "BAD",
			audience:   "AUDIENCE",
			expectCode: codes.InvalidArgument,
			expectMsg:  "unable to parse JWT token",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Failed to validate JWT",
					Data: logrus.Fields{
						"audience":      "AUDIENCE",
						"service":       "WorkloadAPI",
						"method":        "ValidateJWTSVID",
						logrus.ErrorKey: "unable to parse JWT token",
					},
				},
			},
		},
		{
			name:       "attest error",
			svid:       "BAD",
			audience:   "AUDIENCE",
			attestErr:  errors.New("ohno"),
			expectCode: codes.Unknown,
			expectMsg:  "ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Workload attestation failed",
					Data: logrus.Fields{
						"audience":      "AUDIENCE",
						"service":       "WorkloadAPI",
						"method":        "ValidateJWTSVID",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name:       "success",
			audience:   "AUDIENCE",
			svid:       svid.Marshal(),
			updates:    updatesWithBundleOnly,
			expectCode: codes.OK,
			expectResponse: &workloadPB.ValidateJWTSVIDResponse{
				SpiffeId: "spiffe://domain.test/workload",
				Claims: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"aud": {
							Kind: &structpb.Value_ListValue{
								ListValue: &structpb.ListValue{
									Values: []*structpb.Value{
										{
											Kind: &structpb.Value_StringValue{
												StringValue: "AUDIENCE",
											},
										},
									},
								},
							},
						},
						"exp": {
							Kind: &structpb.Value_NumberValue{
								NumberValue: svid.Claims["exp"].(float64),
							},
						},
						"iat": {
							Kind: &structpb.Value_NumberValue{
								NumberValue: svid.Claims["iat"].(float64),
							},
						},
						"iss": {
							Kind: &structpb.Value_StringValue{
								StringValue: "FAKECA",
							},
						},
						"sub": {
							Kind: &structpb.Value_StringValue{
								StringValue: "spiffe://domain.test/workload",
							},
						},
					},
				},
			},
		},
		{
			name:       "success with federated SVID",
			audience:   "AUDIENCE",
			svid:       federatedSVID.Marshal(),
			updates:    updatesWithFederatedBundle,
			expectCode: codes.OK,
			expectResponse: &workloadPB.ValidateJWTSVIDResponse{
				SpiffeId: "spiffe://domain2.test/federated-workload",
				Claims: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"aud": {
							Kind: &structpb.Value_ListValue{
								ListValue: &structpb.ListValue{
									Values: []*structpb.Value{
										{
											Kind: &structpb.Value_StringValue{
												StringValue: "AUDIENCE",
											},
										},
									},
								},
							},
						},
						"exp": {
							Kind: &structpb.Value_NumberValue{
								NumberValue: federatedSVID.Claims["exp"].(float64),
							},
						},
						"sub": {
							Kind: &structpb.Value_StringValue{
								StringValue: "spiffe://domain2.test/federated-workload",
							},
						},
					},
				},
			},
		},
		{
			name:                    "success with federated SVID with allowed foreign claims",
			audience:                "AUDIENCE",
			svid:                    federatedSVID.Marshal(),
			updates:                 updatesWithFederatedBundle,
			expectCode:              codes.OK,
			allowedForeignJWTClaims: map[string]struct{}{"iat": {}, "iss": {}},
			expectResponse: &workloadPB.ValidateJWTSVIDResponse{
				SpiffeId: "spiffe://domain2.test/federated-workload",
				Claims: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"aud": {
							Kind: &structpb.Value_ListValue{
								ListValue: &structpb.ListValue{
									Values: []*structpb.Value{
										{
											Kind: &structpb.Value_StringValue{
												StringValue: "AUDIENCE",
											},
										},
									},
								},
							},
						},
						"iat": {
							Kind: &structpb.Value_NumberValue{
								NumberValue: federatedSVID.Claims["iat"].(float64),
							},
						},
						"iss": {
							Kind: &structpb.Value_StringValue{
								StringValue: "FAKECA",
							},
						},
						"exp": {
							Kind: &structpb.Value_NumberValue{
								NumberValue: federatedSVID.Claims["exp"].(float64),
							},
						},
						"sub": {
							Kind: &structpb.Value_StringValue{
								StringValue: "spiffe://domain2.test/federated-workload",
							},
						},
					},
				},
			},
		},
		{
			name:       "failure with federated SVID",
			audience:   "AUDIENCE",
			svid:       federatedSVID.Marshal(),
			updates:    updatesWithBundleOnly,
			expectCode: codes.InvalidArgument,
			expectMsg:  `no keys found for trust domain "domain2.test"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Failed to validate JWT",
					Data: logrus.Fields{
						"audience":      "AUDIENCE",
						"service":       "WorkloadAPI",
						"method":        "ValidateJWTSVID",
						logrus.ErrorKey: `no keys found for trust domain "domain2.test"`,
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			params := testParams{
				Updates:                 tt.updates,
				AttestErr:               tt.attestErr,
				ExpectLogs:              tt.expectLogs,
				AllowedForeignJWTClaims: tt.allowedForeignJWTClaims,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					resp, err := client.ValidateJWTSVID(ctx, &workloadPB.ValidateJWTSVIDRequest{
						Svid:     tt.svid,
						Audience: tt.audience,
					})
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					if tt.expectCode != codes.OK {
						assert.Nil(t, resp)
						return
					}
					spiretest.AssertProtoEqual(t, tt.expectResponse, resp)
				})
		})
	}
}

type testParams struct {
	CA                            *testca.CA
	Identities                    []cache.Identity
	Updates                       []*cache.WorkloadUpdate
	AttestErr                     error
	ManagerErr                    error
	ExpectLogs                    []spiretest.LogEntry
	AsPID                         int
	AllowUnauthenticatedVerifiers bool
	AllowedForeignJWTClaims       map[string]struct{}
}

func runTest(t *testing.T, params testParams, fn func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient)) {
	log, logHook := test.NewNullLogger()

	manager := &FakeManager{
		ca:         params.CA,
		identities: params.Identities,
		updates:    params.Updates,
		err:        params.ManagerErr,
	}

	handler := workload.New(workload.Config{
		TrustDomain:                   td,
		Manager:                       manager,
		Attestor:                      &FakeAttestor{err: params.AttestErr},
		AllowUnauthenticatedVerifiers: params.AllowUnauthenticatedVerifiers,
		AllowedForeignJWTClaims:       params.AllowedForeignJWTClaims,
	})

	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.Chain(
		middleware.WithLogger(log),
		middleware.Preprocess(func(ctx context.Context, fullMethod string, req interface{}) (context.Context, error) {
			return rpccontext.WithCallerPID(ctx, params.AsPID), nil
		}),
	))

	server := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)
	workloadPB.RegisterSpiffeWorkloadAPIServer(server, handler)
	addr := spiretest.ServeGRPCServerOnTempUDSSocket(t, server)
	t.Cleanup(func() { server.Stop() })

	// Provide a cancelable context to ensure the stream is always
	// closed when the test case is done, and also to ensure that
	// any unexpected blocking call is timed out.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "unix:"+addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	fn(ctx, workloadPB.NewSpiffeWorkloadAPIClient(conn))

	cancel()
	server.GracefulStop()

	assert.Equal(t, 0, manager.Subscribers(), "there should be no more subscribers")

	spiretest.AssertLogs(t, logHook.AllEntries(), params.ExpectLogs)
}

type FakeManager struct {
	ca          *testca.CA
	identities  []cache.Identity
	updates     []*cache.WorkloadUpdate
	subscribers int32
	err         error
}

func (m *FakeManager) MatchingRegistrationEntries(selectors []*common.Selector) []*common.RegistrationEntry {
	out := make([]*common.RegistrationEntry, 0, len(m.identities))
	for _, identity := range m.identities {
		out = append(out, identity.Entry)
	}
	return out
}

func (m *FakeManager) FetchJWTSVID(ctx context.Context, spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, error) {
	svid := m.ca.CreateJWTSVID(spiffeID, audience)
	if m.err != nil {
		return nil, m.err
	}
	return &client.JWTSVID{
		Token: svid.Marshal(),
	}, nil
}

func (m *FakeManager) SubscribeToCacheChanges(ctx context.Context, selectors cache.Selectors) (cache.Subscriber, error) {
	if m.err != nil {
		return nil, m.err
	}
	atomic.AddInt32(&m.subscribers, 1)
	return newFakeSubscriber(m, m.updates), nil
}

func (m *FakeManager) FetchWorkloadUpdate(selectors []*common.Selector) *cache.WorkloadUpdate {
	if len(m.updates) == 0 {
		return &cache.WorkloadUpdate{}
	}
	return m.updates[0]
}

func (m *FakeManager) Subscribers() int {
	return int(atomic.LoadInt32(&m.subscribers))
}

func (m *FakeManager) subscriberDone() {
	atomic.AddInt32(&m.subscribers, -1)
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

type FakeAttestor struct {
	selectors []*common.Selector
	err       error
}

func (a *FakeAttestor) Attest(ctx context.Context) ([]*common.Selector, error) {
	return a.selectors, a.err
}

func identityFromX509SVID(svid *x509svid.SVID) cache.Identity {
	return cache.Identity{
		Entry:      &common.RegistrationEntry{SpiffeId: svid.ID.String()},
		PrivateKey: svid.PrivateKey,
		SVID:       svid.Certificates,
	}
}

func utilBundleFromBundle(t *testing.T, bundle *spiffebundle.Bundle) *bundleutil.Bundle {
	b, err := bundleutil.BundleFromProto(commonBundleFromBundle(t, bundle))
	require.NoError(t, err)
	return b
}

func commonBundleFromBundle(t *testing.T, bundle *spiffebundle.Bundle) *common.Bundle {
	bundleProto := &common.Bundle{
		TrustDomainId: bundle.TrustDomain().IDString(),
	}
	for _, x509Authority := range bundle.X509Authorities() {
		bundleProto.RootCas = append(bundleProto.RootCas, &common.Certificate{
			DerBytes: x509Authority.Raw,
		})
	}
	for keyID, jwtAuthority := range bundle.JWTAuthorities() {
		bundleProto.JwtSigningKeys = append(bundleProto.JwtSigningKeys, &common.PublicKey{
			Kid:       keyID,
			PkixBytes: pkixFromPublicKey(t, jwtAuthority),
		})
	}
	return bundleProto
}

func pkcs8FromSigner(t *testing.T, key crypto.Signer) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return keyBytes
}

func pkixFromPublicKey(t *testing.T, publicKey crypto.PublicKey) []byte {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	return keyBytes
}
