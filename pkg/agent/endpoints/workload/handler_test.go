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
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	td  = spiffeid.RequireTrustDomainFromString("domain.test")
	td2 = spiffeid.RequireTrustDomainFromString("domain2.test")

	workloadID = spiffeid.RequireFromPath(td, "/workload")
)

func TestFetchX509SVID(t *testing.T) {
	ca := testca.New(t, td)

	now := time.Now().Unix()
	x509SVID0 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/aaa"))
	x509SVID0.Hint = "internal"
	x509SVID1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	x509SVID1.Hint = "internal"
	x509SVID2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/two"))
	x509SVID3 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/three"))
	x509SVID3.Hint = "internal"
	x509SVID4 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/four"))
	x509SVID4.Hint = "internal"
	x509SVID5 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/five"))
	bundle := ca.Bundle()
	federatedBundle := testca.New(t, td2).Bundle()

	identities := []cache.Identity{
		identityFromX509SVID(x509SVID0, "id0"),
		identityFromX509SVID(x509SVID1, "id1"),
		identityFromX509SVID(x509SVID2, "id2"),
		identityFromX509SVID(x509SVID3, "id3"),
		identityFromX509SVID(x509SVID4, "id4"),
		identityFromX509SVID(x509SVID5, "id5"),
	}
	identities[0].Entry.CreatedAt = now
	identities[1].Entry.CreatedAt = now
	identities[3].Entry.CreatedAt = now + 3600
	identities[4].Entry.CreatedAt = now + 7200

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
					identities[1],
				},
				Bundle: bundle,
				FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
					federatedBundle.TrustDomain(): federatedBundle,
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
						Hint:        "internal",
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
						identities[1],
						identities[2],
					},
					Bundle: bundle,
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
						Hint:        "internal",
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
		{
			name: "identities with duplicated hints",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: identities,
					Bundle:     bundle,
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.X509SVIDResponse{
				Svids: []*workloadPB.X509SVID{
					{
						SpiffeId:    x509SVID0.ID.String(),
						X509Svid:    x509util.DERFromCertificates(x509SVID0.Certificates),
						X509SvidKey: pkcs8FromSigner(t, x509SVID0.PrivateKey),
						Bundle:      x509util.DERFromCertificates(bundle.X509Authorities()),
						Hint:        "internal",
					},
					{
						SpiffeId:    x509SVID2.ID.String(),
						X509Svid:    x509util.DERFromCertificates(x509SVID2.Certificates),
						X509SvidKey: pkcs8FromSigner(t, x509SVID2.PrivateKey),
						Bundle:      x509util.DERFromCertificates(bundle.X509Authorities()),
					},
					{
						SpiffeId:    x509SVID5.ID.String(),
						X509Svid:    x509util.DERFromCertificates(x509SVID5.Certificates),
						X509SvidKey: pkcs8FromSigner(t, x509SVID5.PrivateKey),
						Bundle:      x509util.DERFromCertificates(bundle.X509Authorities()),
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Ignoring entry with duplicate hint",
					Data: logrus.Fields{
						telemetry.RegistrationID: "id1",
						telemetry.Hint:           "internal",
						telemetry.Method:         "FetchX509SVID",
						telemetry.Service:        "WorkloadAPI",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Ignoring entry with duplicate hint",
					Data: logrus.Fields{
						telemetry.RegistrationID: "id3",
						telemetry.Hint:           "internal",
						telemetry.Method:         "FetchX509SVID",
						telemetry.Service:        "WorkloadAPI",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Ignoring entry with duplicate hint",
					Data: logrus.Fields{
						telemetry.RegistrationID: "id4",
						telemetry.Hint:           "internal",
						telemetry.Method:         "FetchX509SVID",
						telemetry.Service:        "WorkloadAPI",
					},
				},
			},
		},
	} {
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
						identityFromX509SVID(x509SVID, "id1"),
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
						identityFromX509SVID(x509SVID, "id1"),
					},
					Bundle: bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle.TrustDomain(): federatedBundle,
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
					Bundle:     bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle.TrustDomain(): federatedBundle,
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
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: bundle,
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: otherBundle,
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
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: bundle,
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: bundle,
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: otherBundle,
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

	now := time.Now().Unix()
	x509SVID0 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/aaa"))
	x509SVID0.Hint = "internal"
	x509SVID1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	x509SVID1.Hint = "internal"
	x509SVID1Dup := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	x509SVID1Dup.Hint = "external"
	x509SVID2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/two"))
	x509SVID3 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/three"))
	x509SVID3.Hint = "internal"
	x509SVID4 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/four"))
	x509SVID4.Hint = "internal"
	x509SVID5 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/five"))

	identities := []cache.Identity{
		identityFromX509SVID(x509SVID0, "id0"),
		identityFromX509SVID(x509SVID1, "id1"),
		identityFromX509SVID(x509SVID2, "id2"),
		identityFromX509SVID(x509SVID3, "id3"),
		identityFromX509SVID(x509SVID4, "id4"),
		identityFromX509SVID(x509SVID5, "id5"),
		identityFromX509SVID(x509SVID1Dup, "id6"),
	}
	identities[0].Entry.CreatedAt = now
	identities[1].Entry.CreatedAt = now
	identities[3].Entry.CreatedAt = now + 3600
	identities[4].Entry.CreatedAt = now + 7200

	type expectedSVID struct {
		spiffeID string
		hint     string
	}

	for _, tt := range []struct {
		name         string
		identities   []cache.Identity
		spiffeID     string
		audience     []string
		attestErr    error
		managerErr   error
		expectCode   codes.Code
		expectMsg    string
		expectedResp []expectedSVID
		expectLogs   []spiretest.LogEntry
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
				identities[1],
				identities[2],
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
				identities[1],
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
				identities[6],
				identities[1],
				identities[2],
			},
			audience:   []string{"AUDIENCE"},
			expectCode: codes.OK,
			expectedResp: []expectedSVID{
				{
					spiffeID: x509SVID1Dup.ID.String(),
					hint:     "external",
				},
				{
					spiffeID: x509SVID1.ID.String(),
					hint:     "internal",
				},
				{
					spiffeID: x509SVID2.ID.String(),
				},
			},
		},
		{
			name: "success specific",
			identities: []cache.Identity{
				identities[1],
				identities[2],
			},
			spiffeID:   x509SVID2.ID.String(),
			audience:   []string{"AUDIENCE"},
			expectCode: codes.OK,
			expectedResp: []expectedSVID{
				{
					spiffeID: x509SVID2.ID.String(),
				},
			},
		},
		{
			name:       "identities with duplicated hints",
			identities: identities,
			audience:   []string{"AUDIENCE"},
			expectCode: codes.OK,
			expectedResp: []expectedSVID{
				{
					spiffeID: x509SVID0.ID.String(),
					hint:     "internal",
				},
				{
					spiffeID: x509SVID2.ID.String(),
				},
				{
					spiffeID: x509SVID5.ID.String(),
				},
				{
					spiffeID: x509SVID1Dup.ID.String(),
					hint:     "external",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Ignoring entry with duplicate hint",
					Data: logrus.Fields{
						telemetry.RegistrationID: "id1",
						telemetry.Hint:           "internal",
						telemetry.Method:         "FetchJWTSVID",
						telemetry.Service:        "WorkloadAPI",
						telemetry.Registered:     "true",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Ignoring entry with duplicate hint",
					Data: logrus.Fields{
						telemetry.RegistrationID: "id3",
						telemetry.Hint:           "internal",
						telemetry.Method:         "FetchJWTSVID",
						telemetry.Service:        "WorkloadAPI",
						telemetry.Registered:     "true",
					},
				},
				{
					Level:   logrus.WarnLevel,
					Message: "Ignoring entry with duplicate hint",
					Data: logrus.Fields{
						telemetry.RegistrationID: "id4",
						telemetry.Hint:           "internal",
						telemetry.Method:         "FetchJWTSVID",
						telemetry.Service:        "WorkloadAPI",
						telemetry.Registered:     "true",
					},
				},
			},
		},
	} {
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
					assert.Len(t, resp.Svids, len(tt.expectedResp))
					for i, svid := range resp.Svids {
						parsedSVID, err := jwtsvid.ParseInsecure(svid.Svid, tt.audience)
						parsedSVID.Hint = svid.Hint
						require.NoError(t, err, "JWT-SVID token is malformed")
						assert.Equal(t, tt.expectedResp[i].spiffeID, parsedSVID.ID.String())
						assert.Equal(t, tt.expectedResp[i].hint, parsedSVID.Hint)
					}
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

	emptyJWKSBytes := indent([]byte(`{"keys": []}`))

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
						identityFromX509SVID(x509SVID, "id1"),
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
						identityFromX509SVID(x509SVID, "id1"),
					},
					Bundle: bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle.TrustDomain(): federatedBundle,
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
					Bundle:     bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle.TrustDomain(): federatedBundle,
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
		{
			name: "federated bundle with JWKS empty keys array",
			updates: []*cache.WorkloadUpdate{
				{
					Identities: []cache.Identity{
						identityFromX509SVID(x509SVID, "id1"),
					},
					Bundle: bundle,
					FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
						federatedBundle.TrustDomain(): spiffebundle.New(federatedBundle.TrustDomain()),
					},
				},
			},
			expectCode: codes.OK,
			expectResp: &workloadPB.JWTBundlesResponse{
				Bundles: map[string][]byte{
					bundle.TrustDomain().IDString():          bundleJWKS,
					federatedBundle.TrustDomain().IDString(): emptyJWKSBytes,
				},
			},
		},
	} {
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
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: bundle,
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: otherBundle,
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
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: bundle,
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: bundle,
		},
		{
			Identities: []cache.Identity{
				identityFromX509SVID(x509SVID, "id1"),
			},
			Bundle: otherBundle,
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
		Bundle: bundle,
	}}

	updatesWithFederatedBundle := []*cache.WorkloadUpdate{{
		Bundle: bundle,
		FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			federatedBundle.TrustDomain(): federatedBundle,
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
			expectMsg:  "unable to parse JWT token: go-jose/go-jose: compact JWS format must have three parts",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Failed to validate JWT",
					Data: logrus.Fields{
						"audience":      "AUDIENCE",
						"service":       "WorkloadAPI",
						"method":        "ValidateJWTSVID",
						logrus.ErrorKey: "unable to parse JWT token: go-jose/go-jose: compact JWS format must have three parts",
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

	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		workloadPB.RegisterSpiffeWorkloadAPIServer(s, handler)
	}, grpctest.Middleware(
		middleware.WithLogger(log),
		middleware.Preprocess(func(ctx context.Context, fullMethod string, req any) (context.Context, error) {
			return rpccontext.WithCallerPID(ctx, params.AsPID), nil
		}),
	), grpctest.OverUDS(),
	)

	conn := server.NewGRPCClient(t)

	// Provide a cancelable context to ensure the stream is always
	// closed when the test case is done, and also to ensure that
	// any unexpected blocking call is timed out.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fn(ctx, workloadPB.NewSpiffeWorkloadAPIClient(conn))
	cancel()

	// Stop the server (draining the handlers)
	server.Stop()

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

func (m *FakeManager) MatchingRegistrationEntries([]*common.Selector) []*common.RegistrationEntry {
	out := make([]*common.RegistrationEntry, 0, len(m.identities))
	for _, identity := range m.identities {
		out = append(out, identity.Entry)
	}
	return out
}

func (m *FakeManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, audience []string) (*client.JWTSVID, error) {
	spiffeID, err := spiffeid.FromString(entry.SpiffeId)
	if err != nil {
		return nil, err
	}

	svid := m.ca.CreateJWTSVID(spiffeID, audience)
	if m.err != nil {
		return nil, m.err
	}
	return &client.JWTSVID{
		Token: svid.Marshal(),
	}, nil
}

func (m *FakeManager) SubscribeToCacheChanges(context.Context, cache.Selectors) (cache.Subscriber, error) {
	if m.err != nil {
		return nil, m.err
	}
	atomic.AddInt32(&m.subscribers, 1)
	return newFakeSubscriber(m, m.updates), nil
}

func (m *FakeManager) FetchWorkloadUpdate([]*common.Selector) *cache.WorkloadUpdate {
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

func (a *FakeAttestor) Attest(context.Context) ([]*common.Selector, error) {
	return a.selectors, a.err
}

func identityFromX509SVID(svid *x509svid.SVID, entryID string) cache.Identity {
	return cache.Identity{
		Entry:      &common.RegistrationEntry{SpiffeId: svid.ID.String(), Hint: svid.Hint, EntryId: entryID},
		PrivateKey: svid.PrivateKey,
		SVID:       svid.Certificates,
	}
}

func pkcs8FromSigner(t *testing.T, key crypto.Signer) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return keyBytes
}
