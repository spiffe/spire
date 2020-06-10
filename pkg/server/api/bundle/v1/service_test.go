package bundle_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
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
	"google.golang.org/grpc/codes"
)

var (
	bundleBytes = []byte(`{
		"keys": [
			{
				"use": "x509-svid",
				"kty": "EC",
				"crv": "P-384",
				"x": "WjB-nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0",
				"y": "Z-0_tDH_r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs_mcmvPqVK9j",
				"x5c": [
					"MIIBzDCCAVOgAwIBAgIJAJM4DhRH0vmuMAoGCCqGSM49BAMEMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUwHhcNMTgwNTEzMTkzMzQ3WhcNMjMwNTEyMTkzMzQ3WjAeMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWjB+nSGSxIYiznb84xu5WGDZj80nL7W1c3zf48Why0ma7Y7mCBKzfQkrgDguI4j0Z+0/tDH/r8gtOtLLrIpuMwWHoe4vbVBFte1vj6Xt6WeE8lXwcCvLs/mcmvPqVK9jo10wWzAdBgNVHQ4EFgQUh6XzV6LwNazA+GTEVOdu07o5yOgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwGQYDVR0RBBIwEIYOc3BpZmZlOi8vbG9jYWwwCgYIKoZIzj0EAwQDZwAwZAIwE4Me13qMC9i6Fkx0h26y09QZIbuRqA9puLg9AeeAAyo5tBzRl1YL0KNEp02VKSYJAjBdeJvqjJ9wW55OGj1JQwDFD7kWeEB6oMlwPbI/5hEY3azJi16I0uN1JSYTSWGSqWc="
				]
			},
			{
				"use": "jwt-svid",
				"kty": "EC",
				"kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
				"crv": "P-256",
				"x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
				"y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
			}
		]
	}`)
	ctx                  = context.Background()
	serverTrustDomain    = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTrustDomain = spiffeid.RequireTrustDomainFromString("another-example.org")
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

			bundle := makeValidCommonBundle(t, federatedTrustDomain)
			if tt.setBundle {
				test.setBundle(t, bundle)
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

			assertCommonBundleWithMask(t, bundle, b, tt.outputMask)
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

			bundle := makeValidCommonBundle(t, serverTrustDomain)
			if tt.setBundle {
				test.setBundle(t, bundle)
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
			assertCommonBundleWithMask(t, bundle, b, tt.outputMask)
		})
	}
}

func TestAppendBundle(t *testing.T) {
	ca := spiffetest.NewCA(t)
	rootCA := ca.Roots()[0]

	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)

	sb := &common.Bundle{
		TrustDomainId: serverTrustDomain.String(),
		RefreshHint:   60,
		RootCas:       []*common.Certificate{{DerBytes: []byte("cert-bytes")}},
		JwtSigningKeys: []*common.PublicKey{
			{
				Kid:       "key-id-1",
				NotAfter:  1590514224,
				PkixBytes: pkixBytes,
			},
		},
	}

	defaultBundle, err := api.BundleToProto(sb)
	require.NoError(t, err)
	expiresAt := time.Now().Add(time.Minute).Unix()
	jwtKey2 := &types.JWTKey{
		PublicKey: pkixBytes,
		KeyId:     "key-id-2",
		ExpiresAt: expiresAt,
	}
	x509Cert := &types.X509Certificate{
		Asn1: rootCA.Raw,
	}
	_, expectedX509Err := x509.ParseCertificates([]byte("malformed"))
	require.Error(t, expectedX509Err)

	_, expectedJWTErr := x509.ParsePKIXPublicKey([]byte("malformed"))
	require.Error(t, expectedJWTErr)

	for _, tt := range []struct {
		name string

		trustDomain  string
		bundle       *types.Bundle
		code         codes.Code
		dsError      error
		err          string
		expectBundle *types.Bundle
		expectLogs   []spiretest.LogEntry
		invalidEntry bool
		noBundle     bool
		inputMask    *types.BundleMask
		outputMask   *types.BundleMask
	}{
		{
			name: "no input or output mask defined",
			bundle: &types.Bundle{
				TrustDomain: serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{
					x509Cert,
				},
				JwtAuthorities: []*types.JWTKey{jwtKey2},
				// SequenceNumber and refresh hint are ignored.
				SequenceNumber: 10,
				RefreshHint:    20,
			},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				RefreshHint:     defaultBundle.RefreshHint,
				JwtAuthorities:  append(defaultBundle.JwtAuthorities, jwtKey2),
				SequenceNumber:  defaultBundle.SequenceNumber,
				X509Authorities: append(defaultBundle.X509Authorities, x509Cert),
			},
		},
		{
			name: "output mask defined",
			bundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
				JwtAuthorities:  []*types.JWTKey{jwtKey2},
			},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				X509Authorities: append(defaultBundle.X509Authorities, x509Cert),
			},
			outputMask: &types.BundleMask{
				X509Authorities: true,
			},
		},
		{
			name: "inputMask defined",
			bundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
				JwtAuthorities:  []*types.JWTKey{jwtKey2},
			},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				RefreshHint:     defaultBundle.RefreshHint,
				JwtAuthorities:  defaultBundle.JwtAuthorities,
				SequenceNumber:  defaultBundle.SequenceNumber,
				X509Authorities: append(defaultBundle.X509Authorities, x509Cert),
			},
			inputMask: &types.BundleMask{
				X509Authorities: true,
			},
		},
		{
			name: "input mask all false",
			bundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
				JwtAuthorities:  []*types.JWTKey{jwtKey2},
			},
			expectBundle: defaultBundle,
			inputMask: &types.BundleMask{
				X509Authorities: false,
				JwtAuthorities:  false,
				RefreshHint:     false,
				SequenceNumber:  false,
			},
		},
		{
			name: "output mask all false",
			bundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
				JwtAuthorities:  []*types.JWTKey{jwtKey2},
			},
			expectBundle: &types.Bundle{TrustDomain: serverTrustDomain.String()},
			outputMask: &types.BundleMask{
				X509Authorities: false,
				JwtAuthorities:  false,
				RefreshHint:     false,
				SequenceNumber:  false,
			},
		},
		{
			name: "no bundle",
			code: codes.InvalidArgument,
			err:  "missing bundle",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: missing bundle",
				},
			},
		},
		{
			name: "malformed trust domain",
			bundle: &types.Bundle{
				TrustDomain: "malformed id",
			},
			code: codes.InvalidArgument,
			err:  `trust domain argument is not a valid SPIFFE ID: "malformed id"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid request: trust domain argument is not a valid SPIFFE ID: "malformed id"`,
					Data: logrus.Fields{
						logrus.ErrorKey: `spiffeid: unable to parse: parse spiffe://malformed id: invalid character " " in host name`,
					},
				},
			},
		},
		{
			name: "no allowed trust domain",
			bundle: &types.Bundle{
				TrustDomain: spiffeid.RequireTrustDomainFromString("another.org").String(),
			},
			code: codes.InvalidArgument,
			err:  "only the trust domain of the server can be appended",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: only the trust domain of the server can be appended",
				},
			},
		},
		{
			name: "malformed X509 authority",
			bundle: &types.Bundle{
				TrustDomain: serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{
					{
						Asn1: []byte("malformed"),
					},
				},
			},
			code: codes.Internal,
			err:  `failed to convert bundle:`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: fmt.Sprintf("unable to parse X.509 authority: %v", expectedX509Err),
					},
				},
			},
		},
		{
			name: "malformed JWT authority",
			bundle: &types.Bundle{
				TrustDomain: serverTrustDomain.String(),
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: []byte("malformed"),
						ExpiresAt: expiresAt,
						KeyId:     "kid2",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to convert bundle",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: fmt.Sprintf("unable to parse JWT authority: %v", expectedJWTErr),
					},
				},
			},
		},
		{
			name: "invalid keyID jwt authority",
			bundle: &types.Bundle{
				TrustDomain: serverTrustDomain.String(),
				JwtAuthorities: []*types.JWTKey{
					{
						PublicKey: jwtKey2.PublicKey,
						KeyId:     "",
					},
				},
			},
			code: codes.Internal,
			err:  "failed to convert bundle",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: "unable to parse JWT authority: missing key ID",
					},
				},
			},
		},
		{
			name: "datasource fails",
			bundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
			},
			code:    codes.Internal,
			dsError: errors.New("some error"),
			err:     "failed to fetch server bundle: some error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch server bundle",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
		},
		{
			name: "server bundle not found",
			bundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
			},
			code: codes.NotFound,
			err:  "failed to fetch server bundle: not found",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch server bundle: not found",
				},
			},
			noBundle: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			if !tt.noBundle {
				test.setBundle(t, sb)
			}
			test.ds.SetError(tt.dsError)

			if tt.invalidEntry {
				_, err := test.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
					Bundle: &common.Bundle{
						TrustDomainId: "malformed",
					},
				})
				require.NoError(t, err)
			}
			resp, err := test.client.AppendBundle(context.Background(), &bundlepb.AppendBundleRequest{
				Bundle:     tt.bundle,
				InputMask:  tt.inputMask,
				OutputMask: tt.outputMask,
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.AssertProtoEqual(t, tt.expectBundle, resp)
		})
	}
}

func TestBatchDeleteFederatedBundle(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	td1 := spiffeid.RequireTrustDomainFromString("td1.org")
	td2 := spiffeid.RequireTrustDomainFromString("td2.org")
	td3 := spiffeid.RequireTrustDomainFromString("td3.org")
	dsBundles := []string{
		serverTrustDomain.String(),
		td1.String(),
		td2.String(),
		td3.String(),
	}

	for _, tt := range []struct {
		name string

		code            codes.Code
		dsError         error
		err             string
		expectLogs      []spiretest.LogEntry
		expectResults   []*bundlepb.BatchDeleteFederatedBundleResponse_Result
		expectDSBundles []string
		trustDomains    []string
	}{
		{
			name: "remove multiple bundles",
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{Status: &types.Status{Code: int32(codes.OK), Message: "OK"}, TrustDomain: td1.String()},
				{Status: &types.Status{Code: int32(codes.OK), Message: "OK"}, TrustDomain: td2.String()},
			},
			expectDSBundles: []string{serverTrustDomain.String(), td3.String()},
			trustDomains:    []string{td1.String(), td2.String()},
		},
		{
			name:            "empty trust domains",
			expectResults:   []*bundlepb.BatchDeleteFederatedBundleResponse_Result{},
			expectDSBundles: dsBundles,
		},
		{
			name: "malformed trust domain",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: malformed trust domain",
					Data: logrus.Fields{
						logrus.ErrorKey:         `spiffeid: unable to parse: parse spiffe://malformed TD: invalid character " " in host name`,
						telemetry.TrustDomainID: "malformed TD",
					},
				},
			},
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: `malformed trust domain: spiffeid: unable to parse: parse spiffe://malformed TD: invalid character " " in host name`,
					},
					TrustDomain: "malformed TD",
				},
			},
			expectDSBundles: dsBundles,
			trustDomains:    []string{"malformed TD"},
		},
		{
			name: "fail on server bundle",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: removing the bundle for the server trust domain is not allowed",
					Data: logrus.Fields{
						telemetry.TrustDomainID: serverTrustDomain.String(),
					},
				},
			},
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "removing the bundle for the server trust domain is not allowed",
					},
					TrustDomain: serverTrustDomain.String(),
				},
			},
			expectDSBundles: dsBundles,
			trustDomains:    []string{serverTrustDomain.String()},
		},
		{
			name: "bundle not found",
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.NotFound),
						Message: "no such bundle",
					},
					TrustDomain: "notfound.org",
				},
			},
			expectDSBundles: dsBundles,
			trustDomains:    []string{"notfound.org"},
		},
		{
			name: "failed to delete",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to delete federated bundle",
					Data: logrus.Fields{
						logrus.ErrorKey:         "datasource fails",
						telemetry.TrustDomainID: td1.String(),
					},
				},
			},
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to delete federated bundle: datasource fails",
					},
					TrustDomain: td1.String(),
				},
			},
			expectDSBundles: dsBundles,
			trustDomains:    []string{td1.String()},
			dsError:         errors.New("datasource fails"),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			test.ds.SetError(tt.dsError)

			// Create all test bundles
			for _, td := range dsBundles {
				_ = createBundle(t, test, td)
			}

			resp, err := test.client.BatchDeleteFederatedBundle(ctx, &bundlepb.BatchDeleteFederatedBundleRequest{
				TrustDomains: tt.trustDomains,
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

				return
			}

			// Validate response
			require.NoError(t, err)
			require.NotNil(t, resp)
			expectResponse := &bundlepb.BatchDeleteFederatedBundleResponse{
				Results: tt.expectResults,
			}

			spiretest.AssertProtoEqual(t, expectResponse, resp)

			// Validate DS content
			dsResp, err := test.ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
			require.NoError(t, err)

			var dsBundles []string
			for _, b := range dsResp.Bundles {
				dsBundles = append(dsBundles, b.TrustDomainId)
			}
			require.Equal(t, tt.expectDSBundles, dsBundles)
		})
	}
}

func TestListFederatedBundles(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	_ = createBundle(t, test, serverTrustDomain.String())

	serverTrustDomain := spiffeid.RequireTrustDomainFromString("td1.org")
	b1 := createBundle(t, test, serverTrustDomain.String())

	federatedTrustDomain := spiffeid.RequireTrustDomainFromString("td2.org")
	b2 := createBundle(t, test, federatedTrustDomain.String())

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
				RefreshHint:     false,
				SequenceNumber:  false,
				X509Authorities: false,
				JwtAuthorities:  false,
			},
		},
		{
			name:          "get only trust domains",
			expectBundles: []*common.Bundle{b1, b2, b3},
			outputMask:    &types.BundleMask{},
		},
		{
			name: "get first page",
			// Returns only one element because server bundle is the first element
			// returned by datastore, and we filter resutls on service
			expectBundles: []*common.Bundle{b1},
			expectToken:   serverTrustDomain.String(),
			pageSize:      2,
		},
		{
			name:          "get second page",
			expectBundles: []*common.Bundle{b2, b3},
			expectToken:   td3.String(),
			pageSize:      2,
			pageToken:     serverTrustDomain.String(),
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
				assertCommonBundleWithMask(t, tt.expectBundles[i], b, tt.outputMask)
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

func TestBatchCreateFederatedBundle(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	_, expectedX509Err := x509.ParseCertificates([]byte("malformed"))
	require.Error(t, expectedX509Err)

	for _, tt := range []struct {
		name            string
		bundlesToCreate []*types.Bundle
		outputMask      *types.BundleMask
		expectedResults []*bundlepb.BatchCreateFederatedBundleResponse_Result
		expectedLogMsgs []spiretest.LogEntry
		dsError         error
	}{
		{
			name:            "Create succeeds",
			bundlesToCreate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			outputMask: &types.BundleMask{
				RefreshHint: true,
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle created successfully for trust domain: "another-example.org"`),
					Bundle: &types.Bundle{
						TrustDomain: "another-example.org",
						RefreshHint: 60,
					},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle created successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:            "Create succeeds with all-false mask",
			bundlesToCreate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			outputMask:      &types.BundleMask{},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle created successfully for trust domain: "another-example.org"`),
					Bundle: &types.Bundle{TrustDomain: federatedTrustDomain.String()},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle created successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:            "Create succeeds with nil mask",
			bundlesToCreate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle created successfully for trust domain: "another-example.org"`),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle created successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:            "Create succeeds if the request has no bundles",
			bundlesToCreate: []*types.Bundle{},
		},
		{
			name: "Create fails if trust domain is not a valid SPIFFE ID",
			bundlesToCreate: []*types.Bundle{
				func() *types.Bundle {
					b := makeValidBundle(t, federatedTrustDomain)
					b.TrustDomain = "//notvalid"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `trust domain argument is not valid: "//notvalid"`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid request: trust domain argument is not valid`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "//notvalid",
						logrus.ErrorKey:         "spiffeid: trust domain is empty",
					},
				},
			},
		},
		{
			name: "Create fails if trust domain is server trust domain",
			bundlesToCreate: []*types.Bundle{
				func() *types.Bundle {
					b := makeValidBundle(t, federatedTrustDomain)
					b.TrustDomain = "example.org"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `creating a federated bundle for the server's own trust domain (example.org) s not allowed`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid request: creating a federated bundle for the server's own trust domain is not allowed`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "example.org",
					},
				},
			},
		},
		{
			name:            "Create fails if bundle already exists",
			bundlesToCreate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain), makeValidBundle(t, federatedTrustDomain)},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle created successfully for trust domain: "another-example.org"`),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
				{
					Status: api.CreateStatus(codes.AlreadyExists, "bundle already exists"),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle created successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle already exists",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         "rpc error: code = AlreadyExists desc = bundle already exists",
					},
				},
			},
		},
		{
			name:            "Create datastore query fails",
			bundlesToCreate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			dsError:         errors.New("datastore error"),
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.Internal, `unable to create bundle: datastore error`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Unable to create bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         "datastore error",
					},
				},
			},
		},
		{
			name: "Malformed bundle",
			bundlesToCreate: []*types.Bundle{
				{
					TrustDomain: federatedTrustDomain.String(),
					X509Authorities: []*types.X509Certificate{
						{
							Asn1: []byte("malformed"),
						},
					},
				},
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.Internal, `failed to convert bundle: unable to parse X.509 authority: %v`, expectedX509Err)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         fmt.Sprintf("unable to parse X.509 authority: %v", expectedX509Err),
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			clearDSBundles(t, test.ds)
			test.ds.SetError(tt.dsError)

			resp, err := test.client.BatchCreateFederatedBundle(context.Background(), &bundlepb.BatchCreateFederatedBundleRequest{
				Bundle:     tt.bundlesToCreate,
				OutputMask: tt.outputMask,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogMsgs)

			require.Equal(t, len(tt.expectedResults), len(resp.Results))
			for i, result := range resp.Results {
				spiretest.RequireProtoEqual(t, tt.expectedResults[i].Status, result.Status)
				spiretest.RequireProtoEqual(t, tt.expectedResults[i].Bundle, result.Bundle)
			}
		})
	}
}

func TestBatchUpdateFederatedBundle(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	_, expectedX509Err := x509.ParseCertificates([]byte("malformed"))
	require.Error(t, expectedX509Err)

	for _, tt := range []struct {
		name              string
		bundlesToUpdate   []*types.Bundle
		preExistentBundle *common.Bundle
		inputMask         *types.BundleMask
		outputMask        *types.BundleMask
		expectedResults   []*bundlepb.BatchCreateFederatedBundleResponse_Result
		expectedLogMsgs   []spiretest.LogEntry
		dsError           error
	}{
		{
			name:              "Update succeeds with nil masks",
			preExistentBundle: &common.Bundle{TrustDomainId: federatedTrustDomain.IDString()},
			bundlesToUpdate: []*types.Bundle{
				makeValidBundle(t, federatedTrustDomain),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle updated successfully for trust domain: "another-example.org"`),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle updated successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:              "Only values set in input mask are updated",
			preExistentBundle: &common.Bundle{TrustDomainId: federatedTrustDomain.IDString()},
			bundlesToUpdate:   []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			inputMask: &types.BundleMask{
				RefreshHint: true,
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle updated successfully for trust domain: "another-example.org"`),
					Bundle: &types.Bundle{
						TrustDomain: federatedTrustDomain.String(),
						RefreshHint: makeValidBundle(t, federatedTrustDomain).RefreshHint,
					},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle updated successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:              "Only values set in output mask are included in the response",
			preExistentBundle: &common.Bundle{TrustDomainId: federatedTrustDomain.IDString()},
			bundlesToUpdate:   []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			outputMask: &types.BundleMask{
				RefreshHint: true,
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.OK, `bundle updated successfully for trust domain: "another-example.org"`),
					Bundle: &types.Bundle{
						TrustDomain: federatedTrustDomain.String(),
						RefreshHint: makeValidBundle(t, federatedTrustDomain).RefreshHint,
					},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle updated successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:            "Update succeeds if the request has no bundles",
			bundlesToUpdate: []*types.Bundle{},
		},
		{
			name: "Update fails if trust domain is not a valid SPIFFE ID",
			bundlesToUpdate: []*types.Bundle{
				func() *types.Bundle {
					b := makeValidBundle(t, federatedTrustDomain)
					b.TrustDomain = "//notvalid"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `trust domain argument is not valid: "//notvalid"`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid request: trust domain argument is not valid`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "//notvalid",
						logrus.ErrorKey:         "spiffeid: trust domain is empty",
					},
				},
			},
		},
		{
			name: "Update fails if trust domain is server trust domain",
			bundlesToUpdate: []*types.Bundle{
				func() *types.Bundle {
					b := makeValidBundle(t, federatedTrustDomain)
					b.TrustDomain = "example.org"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `updating a federated bundle for the server's own trust domain (example.org) s not allowed`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid request: updating a federated bundle for the server's own trust domain is not allowed`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "example.org",
					},
				},
			},
		},
		{
			name:            "Update fails if bundle does not exists",
			bundlesToUpdate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.NotFound, "bundle not found"),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle not found",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         "rpc error: code = NotFound desc = no such bundle",
					},
				},
			},
		},
		{
			name:            "Update datastore query fails",
			bundlesToUpdate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			dsError:         errors.New("datastore error"),
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.Internal, `unable to update bundle: datastore error`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Unable to update bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         "datastore error",
					},
				},
			},
		},
		{
			name: "Invalid bundle provided",
			bundlesToUpdate: []*types.Bundle{
				{
					TrustDomain: federatedTrustDomain.String(),
					X509Authorities: []*types.X509Certificate{
						{
							Asn1: []byte("malformed"),
						},
					},
				},
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.Internal, fmt.Sprintf("failed to convert bundle: unable to parse X.509 authority: %v", expectedX509Err))},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         fmt.Sprintf("unable to parse X.509 authority: %v", expectedX509Err),
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			clearDSBundles(t, test.ds)

			if tt.preExistentBundle != nil {
				_, err := test.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
					Bundle: tt.preExistentBundle,
				})
				require.NoError(t, err)
			}

			test.ds.SetError(tt.dsError)

			resp, err := test.client.BatchUpdateFederatedBundle(context.Background(), &bundlepb.BatchUpdateFederatedBundleRequest{
				Bundle:     tt.bundlesToUpdate,
				InputMask:  tt.inputMask,
				OutputMask: tt.outputMask,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogMsgs)

			require.Equal(t, len(tt.expectedResults), len(resp.Results))
			for i, result := range resp.Results {
				spiretest.RequireProtoEqual(t, tt.expectedResults[i].Status, result.Status)
				spiretest.RequireProtoEqual(t, tt.expectedResults[i].Bundle, result.Bundle)
			}
		})
	}
}

func assertCommonBundleWithMask(t *testing.T, expected *common.Bundle, actual *types.Bundle, m *types.BundleMask) {
	exp, err := api.BundleToProto(expected)
	require.NoError(t, err)
	assertBundleWithMask(t, exp, actual, m)
}

func assertBundleWithMask(t *testing.T, expected, actual *types.Bundle, m *types.BundleMask) {
	if expected == nil {
		require.Nil(t, actual)
		return
	}

	require.Equal(t, spiffeid.RequireTrustDomainFromString(expected.TrustDomain).String(), actual.TrustDomain)

	if m == nil || m.RefreshHint {
		require.Equal(t, expected.RefreshHint, actual.RefreshHint)
	} else {
		require.Zero(t, actual.RefreshHint)
	}

	if m == nil || m.JwtAuthorities {
		require.Equal(t, expected, actual)
	} else {
		require.Zero(t, actual.JwtAuthorities)
	}

	if m == nil || m.X509Authorities {
		require.Equal(t, expected.X509Authorities, actual.X509Authorities)
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
	ds      *fakedatastore.DataStore
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
		TrustDomain: serverTrustDomain,
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

func makeValidBundle(t *testing.T, td spiffeid.TrustDomain) *types.Bundle {
	b, err := spiffebundle.Parse(td, bundleBytes)
	require.NoError(t, err)

	return &types.Bundle{
		TrustDomain: b.TrustDomain().String(),
		RefreshHint: 60,
		X509Authorities: func(certs []*x509.Certificate) []*types.X509Certificate {
			var authorities []*types.X509Certificate
			for _, c := range certs {
				authorities = append(authorities, &types.X509Certificate{
					Asn1: c.Raw,
				})
			}
			return authorities
		}(b.X509Authorities()),

		JwtAuthorities: func(map[string]crypto.PublicKey) []*types.JWTKey {
			var authorities []*types.JWTKey
			for _, val := range authorities {
				authorities = append(authorities, &types.JWTKey{
					PublicKey: val.PublicKey,
					KeyId:     val.KeyId,
					ExpiresAt: val.ExpiresAt,
				})
			}
			return authorities
		}(b.JWTAuthorities()),
	}
}

func makeValidCommonBundle(t *testing.T, td spiffeid.TrustDomain) *common.Bundle {
	b, err := api.ProtoToBundle(makeValidBundle(t, td))
	require.NoError(t, err)
	return b
}

func clearDSBundles(t *testing.T, ds datastore.DataStore) {
	ctx := context.Background()
	resp, err := ds.ListBundles(ctx, &datastore.ListBundlesRequest{})
	require.NoError(t, err)

	for _, b := range resp.Bundles {
		_, err = ds.DeleteBundle(context.Background(), &datastore.DeleteBundleRequest{
			TrustDomainId: b.TrustDomainId,
		})
		require.NoError(t, err)
	}
}
