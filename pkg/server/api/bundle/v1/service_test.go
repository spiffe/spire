package bundle_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/bundle/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	bundlepb "github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	ctx         = context.Background()
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
	tdBundle    = &common.Bundle{
		TrustDomainId: "spiffe://example.org",
		RefreshHint:   60,
		RootCas:       []*common.Certificate{{DerBytes: []byte("cert-bytes-0")}},
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "key-id-0",
				NotAfter:  1590514224,
				PkixBytes: []byte("key-bytes-0"),
			},
		},
	}
	federatedBundle = &common.Bundle{
		TrustDomainId: "spiffe://another-example.org",
		RefreshHint:   60,
		RootCas:       []*common.Certificate{{DerBytes: []byte("cert-bytes-1")}},
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "key-id-1",
				NotAfter:  1590514224,
				PkixBytes: []byte("key-bytes-1"),
			},
		},
	}
)

func TestGetFederatedBundle(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	for _, tt := range []struct {
		name        string
		trustDomain string
		err         string
		logMsg      string
		outputMask  *types.BundleMask
		isAdmin     bool
		isAgent     bool
		isLocal     bool
		setBundle   bool
	}{
		{
			name:    "Trust domain is empty",
			isAdmin: true,
			err:     `trust domain argument is not a valid SPIFFE ID: ""`,
			logMsg:  `Trust domain argument is not a valid SPIFFE ID: ""`,
		},
		{
			name:        "Trust domain is not a valid trust domain",
			isAdmin:     true,
			trustDomain: "//not-valid",
			err:         `trust domain argument is not a valid SPIFFE ID: "//not-valid"`,
			logMsg:      `Trust domain argument is not a valid SPIFFE ID: "//not-valid"`,
		},
		{
			name:        "The given trust domain is server's own trust domain",
			isAdmin:     true,
			trustDomain: "example.org",
			err:         `"example.org" is this server own trust domain, use GetBundle RPC instead`,
			logMsg:      `"example.org" is this server own trust domain, use GetBundle RPC instead`,
		},
		{
			name:        "Trust domain not found",
			isAdmin:     true,
			trustDomain: "another-example.org",
			err:         `bundle for "another-example.org" not found`,
			logMsg:      `Bundle for "another-example.org" not found`,
		},
		{
			name:        "Get federated bundle do not returns fields filtered by mask",
			isAdmin:     true,
			trustDomain: "another-example.org",
			setBundle:   true,
			outputMask: &types.BundleMask{
				TrustDomain:     false,
				RefreshHint:     false,
				SequenceNumber:  false,
				X509Authorities: false,
				JwtAuthorities:  false,
			},
		},
		{
			name:        "Get federated bundle succeeds for admin workloads",
			isAdmin:     true,
			trustDomain: "another-example.org",
			setBundle:   true,
		},
		{
			name:        "Get federated bundle succeeds for local workloads",
			isLocal:     true,
			trustDomain: "another-example.org",
			setBundle:   true,
		},
		{
			name:        "Get federated bundle succeeds for agent workload",
			isAgent:     true,
			trustDomain: "another-example.org",
			setBundle:   true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.isAdmin = tt.isAdmin
			test.isAgent = tt.isAgent
			test.isLocal = tt.isLocal

			if tt.setBundle {
				test.setBundle(t, federatedBundle)
			}

			b, err := test.client.GetFederatedBundle(context.Background(), &bundlepb.GetFederatedBundleRequest{
				TrustDomain: tt.trustDomain,
				OutputMask:  tt.outputMask,
			})

			if tt.err != "" {
				require.Nil(t, b)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				require.Contains(t, test.logHook.LastEntry().Message, tt.logMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, b)
			assertBundleWithMask(t, federatedBundle, b, tt.outputMask)
		})
	}
}

func TestGetBundle(t *testing.T) {
	for _, tt := range []struct {
		name       string
		err        string
		logMsg     string
		outputMask *types.BundleMask
		setBundle  bool
	}{
		{
			name:      "Get bundle returns bundle",
			setBundle: true,
		},
		{
			name:   "Bundle not found",
			err:    `bundle not found`,
			logMsg: `Bundle not found`,
		},
		{
			name:      "Get bundle does not return fields filtered by mask",
			setBundle: true,
			outputMask: &types.BundleMask{
				TrustDomain:     false,
				RefreshHint:     false,
				SequenceNumber:  false,
				X509Authorities: false,
				JwtAuthorities:  false,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			if tt.setBundle {
				test.setBundle(t, tdBundle)
			}

			b, err := test.client.GetBundle(context.Background(), &bundlepb.GetBundleRequest{
				OutputMask: tt.outputMask,
			})

			if tt.err != "" {
				require.Nil(t, b)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				require.Contains(t, test.logHook.LastEntry().Message, tt.logMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, b)
			assertBundleWithMask(t, tdBundle, b, tt.outputMask)
		})
	}
}

func TestListFederatedBundles(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	_ = createBundle(t, test, trustDomain.String())

	td1 := spiffeid.RequireTrustDomainFromString("td1.org")
	b1 := createBundle(t, test, td1.String())

	td2 := spiffeid.RequireTrustDomainFromString("td2.org")
	b2 := createBundle(t, test, td2.String())

	td3 := spiffeid.RequireTrustDomainFromString("td3.org")
	b3 := createBundle(t, test, td3.String())

	for _, tt := range []struct {
		name          string
		code          codes.Code
		err           string
		expectBundles []*common.Bundle
		expectLogs    []spiretest.LogEntry
		expectToken   string
		isInvalidTD   bool
		outputMask    *types.BundleMask
		pageSize      int32
		pageToken     string
	}{
		{
			name:          "no returns fields filtered by mask",
			expectBundles: []*common.Bundle{b1, b2, b3},
			outputMask: &types.BundleMask{
				TrustDomain:     false,
				RefreshHint:     false,
				SequenceNumber:  false,
				X509Authorities: false,
				JwtAuthorities:  false,
			},
		},
		{
			name:          "get only trust domains",
			expectBundles: []*common.Bundle{b1, b2, b3},
			outputMask: &types.BundleMask{
				TrustDomain: true,
			},
		},
		{
			name: "get first page",
			// Returns only one element because server bundle is the first element
			// returned by datastore, and we filter resutls on service
			expectBundles: []*common.Bundle{b1},
			expectToken:   td1.String(),
			pageSize:      2,
		},
		{
			name:          "get second page",
			expectBundles: []*common.Bundle{b2, b3},
			expectToken:   td3.String(),
			pageSize:      2,
			pageToken:     td1.String(),
		},
		{
			name:          "get third page",
			expectBundles: []*common.Bundle{},
			expectToken:   "",
			pageSize:      2,
			pageToken:     td3.String(),
		},
		{
			name: "datastore returns invalid trust domain",
			code: codes.Internal,
			err:  `bundle has an invalid trust domain ID: "invalid TD"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle has an invalid trust domain ID",
					Data: logrus.Fields{
						logrus.ErrorKey:         `spiffeid: unable to parse: parse spiffe://invalid TD: invalid character " " in host name`,
						telemetry.TrustDomainID: "invalid TD",
					},
				},
			},
			isInvalidTD: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			// Create an invalid bundle to test mask failing
			if tt.isInvalidTD {
				invalidBundle := createBundle(t, test, "invalid TD")
				defer func() {
					_, _ = test.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
						TrustDomainId: invalidBundle.TrustDomainId,
					})
				}()
			}

			resp, err := test.client.ListFederatedBundles(ctx, &bundlepb.ListFederatedBundlesRequest{
				OutputMask: tt.outputMask,
				PageSize:   tt.pageSize,
				PageToken:  tt.pageToken,
			})

			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			require.Equal(t, tt.expectToken, resp.NextPageToken)
			require.Len(t, resp.Bundles, len(tt.expectBundles))

			for i, b := range resp.Bundles {
				assertBundleWithMask(t, tt.expectBundles[i], b, tt.outputMask)
			}
		})
	}
}

func createBundle(t *testing.T, test *serviceTest, td string) *common.Bundle {
	b := &common.Bundle{
		TrustDomainId: td,
		RefreshHint:   60,
		RootCas:       []*common.Certificate{{DerBytes: []byte(fmt.Sprintf("cert-bytes-%s", td))}},
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       fmt.Sprintf("key-id-%s", td),
				NotAfter:  time.Now().Add(time.Minute).Unix(),
				PkixBytes: []byte(fmt.Sprintf("key-bytes-%s", td)),
			},
		},
	}
	test.setBundle(t, b)

	return b
}

func assertBundleWithMask(t *testing.T, expected *common.Bundle, actual *types.Bundle, m *types.BundleMask) {
	if m == nil || m.TrustDomain {
		require.Equal(t, spiffeid.RequireTrustDomainFromString(expected.TrustDomainId).String(), actual.TrustDomain)
	} else {
		require.Zero(t, actual.TrustDomain)
	}

	if m == nil || m.RefreshHint {
		require.Equal(t, expected.RefreshHint, actual.RefreshHint)
	} else {
		require.Zero(t, actual.RefreshHint)
	}

	if m == nil || m.JwtAuthorities {
		require.Equal(t, len(expected.JwtSigningKeys), len(actual.JwtAuthorities))
		require.Equal(t, expected.JwtSigningKeys[0].Kid, actual.JwtAuthorities[0].KeyId)
		require.Equal(t, expected.JwtSigningKeys[0].NotAfter, actual.JwtAuthorities[0].ExpiresAt)
		require.Equal(t, expected.JwtSigningKeys[0].PkixBytes, actual.JwtAuthorities[0].PublicKey)
	} else {
		require.Zero(t, actual.RefreshHint)
	}

	if m == nil || m.X509Authorities {
		require.Equal(t, len(expected.RootCas), len(actual.X509Authorities))
		require.Equal(t, expected.RootCas[0].DerBytes, actual.X509Authorities[0].Asn1)
	} else {
		require.Zero(t, actual.X509Authorities)
	}
}

func (c *serviceTest) setBundle(t *testing.T, b *common.Bundle) {
	req := &datastore.SetBundleRequest{
		Bundle: b,
	}

	_, err := c.ds.SetBundle(context.Background(), req)
	require.NoError(t, err)
}

type serviceTest struct {
	client  bundlepb.BundleClient
	ds      datastore.DataStore
	logHook *test.Hook
	done    func()
	isAdmin bool
	isAgent bool
	isLocal bool
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	ds := fakedatastore.New()
	service := bundle.New(bundle.Config{
		Datastore:   ds,
		TrustDomain: trustDomain,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		bundle.RegisterService(s, service)
	}

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		if test.isAdmin {
			ctx = rpccontext.WithCallerAdminEntries(ctx, []*types.Entry{{Admin: true}})
		}
		if test.isAgent {
			ctx = rpccontext.WithAgentCaller(ctx)
		}
		if test.isLocal {
			ctx = rpccontext.WithCallerAddr(ctx, &net.UnixAddr{
				Net:  "unix",
				Name: "addr.sock",
			})
		}
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = bundlepb.NewBundleClient(conn)

	return test
}
