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
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/bundle/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	bundlepb "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		expectLogs  []spiretest.LogEntry
		outputMask  *types.BundleMask
		isAdmin     bool
		isAgent     bool
		isLocal     bool
		setBundle   bool
	}{
		{
			name:    "Trust domain is empty",
			isAdmin: true,
			err:     "rpc error: code = InvalidArgument desc = trust domain argument is not valid: spiffeid: trust domain is empty",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: trust domain argument is not valid",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "",
						logrus.ErrorKey:         "spiffeid: trust domain is empty",
					},
				},
			},
		},
		{
			name:        "Trust domain is not a valid trust domain",
			isAdmin:     true,
			trustDomain: "malformed id",
			err:         `rpc error: code = InvalidArgument desc = trust domain argument is not valid: spiffeid: unable to parse: parse "spiffe://malformed id": invalid character " " in host name`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: trust domain argument is not valid",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "malformed id",
						logrus.ErrorKey:         `spiffeid: unable to parse: parse "spiffe://malformed id": invalid character " " in host name`,
					},
				},
			},
		},
		{
			name:        "The given trust domain is server's own trust domain",
			isAdmin:     true,
			trustDomain: "example.org",
			err:         "rpc error: code = InvalidArgument desc = getting a federated bundle for the server's own trust domain is not allowed",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: getting a federated bundle for the server's own trust domain is not allowed",
					Data: logrus.Fields{
						telemetry.TrustDomainID: serverTrustDomain.String(),
					},
				},
			},
		},
		{
			name:        "Trust domain not found",
			isAdmin:     true,
			trustDomain: "another-example.org",
			err:         `rpc error: code = NotFound desc = bundle not found`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle not found",
					Data: logrus.Fields{
						telemetry.TrustDomainID: federatedTrustDomain.String(),
					},
				},
			},
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
			test.logHook.Reset()
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

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

			if tt.err != "" {
				require.Nil(t, b)
				require.Error(t, err)
				require.EqualError(t, err, tt.err)
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
	ca := testca.New(t, serverTrustDomain)
	rootCA := ca.X509Authorities()[0]

	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)

	sb := &common.Bundle{
		TrustDomainId: serverTrustDomain.IDString(),
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

		trustDomain     string
		x509Authorities []*types.X509Certificate
		jwtAuthorities  []*types.JWTKey
		code            codes.Code
		dsError         error
		err             string
		expectBundle    *types.Bundle
		expectLogs      []spiretest.LogEntry
		invalidEntry    bool
		noBundle        bool
		outputMask      *types.BundleMask
	}{
		{
			name:            "no output mask defined",
			x509Authorities: []*types.X509Certificate{x509Cert},
			jwtAuthorities:  []*types.JWTKey{jwtKey2},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				RefreshHint:     defaultBundle.RefreshHint,
				SequenceNumber:  defaultBundle.SequenceNumber,
				X509Authorities: append(defaultBundle.X509Authorities, x509Cert),
				JwtAuthorities:  append(defaultBundle.JwtAuthorities, jwtKey2),
			},
		},
		{
			name:            "output mask defined",
			x509Authorities: []*types.X509Certificate{x509Cert},
			jwtAuthorities:  []*types.JWTKey{jwtKey2},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				X509Authorities: append(defaultBundle.X509Authorities, x509Cert),
			},
			outputMask: &types.BundleMask{
				X509Authorities: true,
			},
		},
		{
			name:            "update only X.509 authorities",
			x509Authorities: []*types.X509Certificate{x509Cert},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				RefreshHint:     defaultBundle.RefreshHint,
				SequenceNumber:  defaultBundle.SequenceNumber,
				JwtAuthorities:  defaultBundle.JwtAuthorities,
				X509Authorities: append(defaultBundle.X509Authorities, x509Cert),
			},
		},
		{
			name:           "update only JWT authorities",
			jwtAuthorities: []*types.JWTKey{jwtKey2},
			expectBundle: &types.Bundle{
				TrustDomain:     defaultBundle.TrustDomain,
				RefreshHint:     defaultBundle.RefreshHint,
				SequenceNumber:  defaultBundle.SequenceNumber,
				JwtAuthorities:  append(defaultBundle.JwtAuthorities, jwtKey2),
				X509Authorities: defaultBundle.X509Authorities,
			},
		},
		{
			name:            "output mask all false",
			x509Authorities: []*types.X509Certificate{x509Cert},
			jwtAuthorities:  []*types.JWTKey{jwtKey2},
			expectBundle:    &types.Bundle{TrustDomain: serverTrustDomain.String()},
			outputMask: &types.BundleMask{
				X509Authorities: false,
				JwtAuthorities:  false,
				RefreshHint:     false,
				SequenceNumber:  false,
			},
		},
		{
			name: "no authorities",
			code: codes.InvalidArgument,
			err:  "no authorities to append",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: no authorities to append",
				},
			},
		},
		{
			name: "malformed X509 authority",
			x509Authorities: []*types.X509Certificate{
				{
					Asn1: []byte("malformed"),
				},
			},
			code: codes.InvalidArgument,
			err:  `failed to convert X.509 authority:`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert X.509 authority",
					Data: logrus.Fields{
						telemetry.TrustDomainID: serverTrustDomain.String(),
						logrus.ErrorKey:         expectedX509Err.Error(),
					},
				},
			},
		},
		{
			name: "malformed JWT authority",
			jwtAuthorities: []*types.JWTKey{
				{
					PublicKey: []byte("malformed"),
					ExpiresAt: expiresAt,
					KeyId:     "kid2",
				},
			},
			code: codes.InvalidArgument,
			err:  "failed to convert JWT authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert JWT authority",
					Data: logrus.Fields{
						telemetry.TrustDomainID: serverTrustDomain.String(),
						logrus.ErrorKey:         expectedJWTErr.Error(),
					},
				},
			},
		},
		{
			name: "invalid keyID jwt authority",
			jwtAuthorities: []*types.JWTKey{
				{
					PublicKey: jwtKey2.PublicKey,
					KeyId:     "",
				},
			},
			code: codes.InvalidArgument,
			err:  "failed to convert JWT authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert JWT authority",
					Data: logrus.Fields{
						telemetry.TrustDomainID: serverTrustDomain.String(),
						logrus.ErrorKey:         "missing key ID",
					},
				},
			},
		},
		{
			name:            "datasource fails",
			x509Authorities: []*types.X509Certificate{x509Cert},
			code:            codes.Internal,
			dsError:         errors.New("some error"),
			err:             "failed to append bundle: some error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to append bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: serverTrustDomain.String(),
						logrus.ErrorKey:         "some error",
					},
				},
			},
		},
		{
			name:            "if bundle not found, a new bundle is created",
			x509Authorities: []*types.X509Certificate{x509Cert},
			jwtAuthorities:  []*types.JWTKey{jwtKey2},
			expectBundle: &types.Bundle{
				TrustDomain:     serverTrustDomain.String(),
				X509Authorities: []*types.X509Certificate{x509Cert},
				JwtAuthorities:  []*types.JWTKey{jwtKey2},
			},
			code:     codes.OK,
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
			test.ds.SetNextError(tt.dsError)

			if tt.invalidEntry {
				_, err := test.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
					Bundle: &common.Bundle{
						TrustDomainId: "malformed",
					},
				})
				require.NoError(t, err)
			}
			resp, err := test.client.AppendBundle(context.Background(), &bundlepb.AppendBundleRequest{
				X509Authorities: tt.x509Authorities,
				JwtAuthorities:  tt.jwtAuthorities,
				OutputMask:      tt.outputMask,
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
		serverTrustDomain.IDString(),
		td1.IDString(),
		td2.IDString(),
		td3.IDString(),
	}
	newEntry := &common.RegistrationEntry{
		EntryId:  "entry1",
		ParentId: "spiffe://example.org/foo",
		SpiffeId: "spiffe://example.org/bar",
		Ttl:      60,
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
		},
		FederatesWith: []string{
			td1.IDString(),
		},
	}

	for _, tt := range []struct {
		name string

		entry           *common.RegistrationEntry
		code            codes.Code
		dsError         error
		err             string
		expectLogs      []spiretest.LogEntry
		expectResults   []*bundlepb.BatchDeleteFederatedBundleResponse_Result
		expectDSBundles []string
		mode            bundlepb.BatchDeleteFederatedBundleRequest_Mode
		trustDomains    []string
	}{
		{
			name: "remove multiple bundles",
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{Status: &types.Status{Code: int32(codes.OK), Message: "OK"}, TrustDomain: td1.String()},
				{Status: &types.Status{Code: int32(codes.OK), Message: "OK"}, TrustDomain: td2.String()},
			},
			expectDSBundles: []string{serverTrustDomain.IDString(), td3.IDString()},
			trustDomains:    []string{td1.String(), td2.String()},
		},
		{
			name:            "empty trust domains",
			expectResults:   []*bundlepb.BatchDeleteFederatedBundleResponse_Result{},
			expectDSBundles: dsBundles,
		},
		{
			name:  "failed to delete with RESTRICT mode",
			entry: newEntry,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to delete federated bundle",
					Data: logrus.Fields{
						logrus.ErrorKey:                     "rpc error: code = FailedPrecondition desc = datastore-sql: cannot delete bundle; federated with 1 registration entries",
						telemetry.TrustDomainID:             "td1.org",
						telemetry.DeleteFederatedBundleMode: "RESTRICT",
					},
				},
			},
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.FailedPrecondition),
						Message: "failed to delete federated bundle: datastore-sql: cannot delete bundle; federated with 1 registration entries",
					},
					TrustDomain: "td1.org",
				},
			},
			mode:            bundlepb.BatchDeleteFederatedBundleRequest_RESTRICT,
			trustDomains:    []string{td1.String()},
			expectDSBundles: dsBundles,
		},
		{
			name:  "delete with DISSOCIATE mode",
			entry: newEntry,
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.OK),
						Message: "OK",
					},
					TrustDomain: "td1.org",
				},
			},
			mode:         bundlepb.BatchDeleteFederatedBundleRequest_DISSOCIATE,
			trustDomains: []string{td1.String()},
			expectDSBundles: []string{
				serverTrustDomain.IDString(),
				td2.IDString(),
				td3.IDString(),
			},
		},
		{
			name:  "delete with DELETE mode",
			entry: newEntry,
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.OK),
						Message: "OK",
					},
					TrustDomain: "td1.org",
				},
			},
			mode:         bundlepb.BatchDeleteFederatedBundleRequest_DELETE,
			trustDomains: []string{td1.String()},
			expectDSBundles: []string{
				serverTrustDomain.IDString(),
				td2.IDString(),
				td3.IDString(),
			},
		},
		{
			name: "malformed trust domain",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: trust domain argument is not valid",
					Data: logrus.Fields{
						logrus.ErrorKey:                     `spiffeid: unable to parse: parse "spiffe://malformed TD": invalid character " " in host name`,
						telemetry.TrustDomainID:             "malformed TD",
						telemetry.DeleteFederatedBundleMode: "RESTRICT",
					},
				},
			},
			expectResults: []*bundlepb.BatchDeleteFederatedBundleResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: `trust domain argument is not valid: spiffeid: unable to parse: parse "spiffe://malformed TD": invalid character " " in host name`,
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
					Message: "Invalid argument: removing the bundle for the server trust domain is not allowed",
					Data: logrus.Fields{
						telemetry.TrustDomainID:             serverTrustDomain.String(),
						telemetry.DeleteFederatedBundleMode: "RESTRICT",
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
						Message: "bundle not found",
					},
					TrustDomain: "notfound.org",
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle not found",
					Data: logrus.Fields{
						telemetry.DeleteFederatedBundleMode: "RESTRICT",
						telemetry.TrustDomainID:             "notfound.org",
					},
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
						logrus.ErrorKey:                     "rpc error: code = Internal desc = datasource fails",
						telemetry.DeleteFederatedBundleMode: "RESTRICT",
						telemetry.TrustDomainID:             td1.String(),
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
			dsError:         status.New(codes.Internal, "datasource fails").Err(),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			// Create all test bundles
			for _, td := range dsBundles {
				_ = createBundle(t, test, td)
			}

			var entryID string
			if tt.entry != nil {
				r, err := test.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
					Entry: tt.entry,
				})
				require.NoError(t, err)
				entryID = r.Entry.EntryId
			}

			// Set datastore error after creating the test bundles
			test.ds.SetNextError(tt.dsError)
			resp, err := test.client.BatchDeleteFederatedBundle(ctx, &bundlepb.BatchDeleteFederatedBundleRequest{
				TrustDomains: tt.trustDomains,
				Mode:         tt.mode,
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

			if entryID != "" {
				fetchEntryResp, err := test.ds.FetchRegistrationEntry(ctx, &datastore.FetchRegistrationEntryRequest{
					EntryId: entryID,
				})
				require.NoError(t, err)
				entry := fetchEntryResp.Entry

				switch tt.mode {
				case bundlepb.BatchDeleteFederatedBundleRequest_RESTRICT:
					require.Equal(t, []string{td1.IDString()}, entry.FederatesWith)
				case bundlepb.BatchDeleteFederatedBundleRequest_DISSOCIATE:
					require.Empty(t, entry.FederatesWith)
				case bundlepb.BatchDeleteFederatedBundleRequest_DELETE:
					require.Nil(t, fetchEntryResp.Entry)
				}
			}
		})
	}
}

func TestPublishJWTAuthority(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	pkixBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYSlUVLqTD8DEnA4F1EWMTf5RXc5lnCxw+5WKJwngEL3rPc9i4Tgzz9riR3I/NiSlkgRO1WsxBusqpC284j9dXA==")
	require.NoError(t, err)
	expiresAt := time.Now().Unix()
	jwtKey1 := &types.JWTKey{
		ExpiresAt: expiresAt,
		KeyId:     "key1",
		PublicKey: pkixBytes,
	}

	_, expectedJWTErr := x509.ParsePKIXPublicKey([]byte("malformed key"))
	require.Error(t, expectedJWTErr)

	for _, tt := range []struct {
		name string

		code           codes.Code
		err            string
		expectLogs     []spiretest.LogEntry
		resultKeys     []*types.JWTKey
		fakeErr        error
		fakeExpectKey  *common.PublicKey
		jwtKey         *types.JWTKey
		rateLimiterErr error
	}{
		{
			name:   "success",
			jwtKey: jwtKey1,
			fakeExpectKey: &common.PublicKey{
				PkixBytes: pkixBytes,
				Kid:       "key1",
				NotAfter:  expiresAt,
			},
			resultKeys: []*types.JWTKey{
				{
					ExpiresAt: expiresAt,
					KeyId:     "key1",
					PublicKey: pkixBytes,
				},
			},
		},
		{
			name:           "rate limit fails",
			jwtKey:         jwtKey1,
			rateLimiterErr: status.Error(codes.Internal, "limit error"),
			code:           codes.Internal,
			err:            "rejecting request due to key publishing rate limiting: limit error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rejecting request due to key publishing rate limiting",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = limit error",
					},
				},
			},
		},
		{
			name: "missing JWT authority",
			code: codes.InvalidArgument,
			err:  "missing JWT authority",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: missing JWT authority",
				},
			},
		},
		{
			name: "malformed key",
			code: codes.InvalidArgument,
			err:  "invalid JWT authority: asn1:",
			jwtKey: &types.JWTKey{
				ExpiresAt: expiresAt,
				KeyId:     "key1",
				PublicKey: []byte("malformed key"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid JWT authority",
					Data: logrus.Fields{
						logrus.ErrorKey: expectedJWTErr.Error(),
					},
				},
			},
		},
		{
			name: "missing key ID",
			code: codes.InvalidArgument,
			err:  "invalid JWT authority: missing key ID",
			jwtKey: &types.JWTKey{
				ExpiresAt: expiresAt,
				PublicKey: jwtKey1.PublicKey,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid JWT authority",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing key ID",
					},
				},
			},
		},
		{
			name:    "fail to publish",
			code:    codes.Internal,
			err:     "failed to publish JWT key: publish error",
			fakeErr: errors.New("publish error"),
			jwtKey:  jwtKey1,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to publish JWT key",
					Data: logrus.Fields{
						logrus.ErrorKey: "publish error",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			// Setup fake
			test.up.t = t
			test.up.err = tt.fakeErr
			test.up.expectKey = tt.fakeExpectKey

			// Setup rate limiter
			test.rateLimiter.count = 1
			test.rateLimiter.err = tt.rateLimiterErr

			resp, err := test.client.PublishJWTAuthority(ctx, &bundlepb.PublishJWTAuthorityRequest{
				JwtAuthority: tt.jwtKey,
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if err != nil {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoEqual(t, &bundlepb.PublishJWTAuthorityResponse{
				JwtAuthorities: tt.resultKeys,
			}, resp)
		})
	}
}

func TestListFederatedBundles(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	_ = createBundle(t, test, serverTrustDomain.IDString())

	serverTrustDomain := spiffeid.RequireTrustDomainFromString("td1.org")
	b1 := createBundle(t, test, serverTrustDomain.IDString())

	federatedTrustDomain := spiffeid.RequireTrustDomainFromString("td2.org")
	b2 := createBundle(t, test, federatedTrustDomain.IDString())

	td3 := spiffeid.RequireTrustDomainFromString("td3.org")
	b3 := createBundle(t, test, td3.IDString())

	for _, tt := range []struct {
		name              string
		code              codes.Code
		err               string
		expectBundlePages [][]*common.Bundle
		expectLogs        []spiretest.LogEntry
		outputMask        *types.BundleMask
		pageSize          int32
	}{
		{
			name:              "all bundles at once with no mask",
			expectBundlePages: [][]*common.Bundle{{b1, b2, b3}},
		},
		{
			name:              "all bundles at once with most permissive mask",
			expectBundlePages: [][]*common.Bundle{{b1, b2, b3}},
			outputMask: &types.BundleMask{
				RefreshHint:     true,
				SequenceNumber:  true,
				X509Authorities: true,
				JwtAuthorities:  true,
			},
		},
		{
			name:              "all bundles at once filtered by mask",
			expectBundlePages: [][]*common.Bundle{{b1, b2, b3}},
			outputMask: &types.BundleMask{
				RefreshHint:     false,
				SequenceNumber:  false,
				X509Authorities: false,
				JwtAuthorities:  false,
			},
		},
		{
			name: "page bundles",
			// Returns only one element because server bundle is the first element
			// returned by datastore, and we filter resutls on service
			expectBundlePages: [][]*common.Bundle{
				{b1},
				{b2, b3},
				{},
			},
			pageSize: 2,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()

			// This limit exceeds the number of pages we should reasonably
			// expect to receive during a test. Exceeding this limit implies
			// that paging is likely broken.
			const pagesLimit = 10

			var pageToken string
			var actualBundlePages [][]*types.Bundle
			for {
				resp, err := test.client.ListFederatedBundles(ctx, &bundlepb.ListFederatedBundlesRequest{
					OutputMask: tt.outputMask,
					PageSize:   tt.pageSize,
					PageToken:  pageToken,
				})
				if tt.err != "" {
					spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
					require.Nil(t, resp)
					spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

					return
				}
				require.NoError(t, err)
				require.NotNil(t, resp)
				actualBundlePages = append(actualBundlePages, resp.Bundles)
				if len(actualBundlePages) > pagesLimit {
					t.Fatalf("exceeded page count limit (%d); paging is likely broken", pagesLimit)
					break
				}
				pageToken = resp.NextPageToken
				if pageToken == "" {
					break
				}
			}

			require.Len(t, actualBundlePages, len(tt.expectBundlePages), "unexpected number of bundle pages")
			for i, actualBundlePage := range actualBundlePages {
				expectBundlePage := tt.expectBundlePages[i]
				require.Len(t, actualBundlePage, len(expectBundlePage), "unexpected number of bundles in page")
				for j, actualBundle := range actualBundlePage {
					expectBundle := expectBundlePage[j]
					assertCommonBundleWithMask(t, expectBundle, actualBundle, tt.outputMask)
				}
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
					Status: api.OK(),
					Bundle: &types.Bundle{
						TrustDomain: "another-example.org",
						RefreshHint: 60,
					},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle created",
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
					Status: api.OK(),
					Bundle: &types.Bundle{TrustDomain: federatedTrustDomain.String()},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle created",
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
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle created",
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
					b.TrustDomain = "malformed id"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `trust domain argument is not valid: spiffeid: unable to parse: parse "spiffe://malformed id": invalid character " " in host name`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid argument: trust domain argument is not valid`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "malformed id",
						logrus.ErrorKey:         `spiffeid: unable to parse: parse "spiffe://malformed id": invalid character " " in host name`,
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
				{Status: api.CreateStatus(codes.InvalidArgument, `creating a federated bundle for the server's own trust domain is not allowed`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid argument: creating a federated bundle for the server's own trust domain is not allowed`,
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
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
				{
					Status: api.CreateStatus(codes.AlreadyExists, "bundle already exists"),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle created",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle already exists",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
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
				{Status: api.CreateStatus(codes.InvalidArgument, `failed to convert bundle: unable to parse X.509 authority: %v`, expectedX509Err)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert bundle",
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
			test.ds.SetNextError(tt.dsError)

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
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle updated",
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
				RefreshHint:     true,
				JwtAuthorities:  true,
				X509Authorities: true,
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle updated",
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
					Status: api.OK(),
					Bundle: &types.Bundle{
						TrustDomain: federatedTrustDomain.String(),
						RefreshHint: makeValidBundle(t, federatedTrustDomain).RefreshHint,
					},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle updated",
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
					b.TrustDomain = "malformed id"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `trust domain argument is not valid: spiffeid: unable to parse: parse "spiffe://malformed id": invalid character " " in host name`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid argument: trust domain argument is not valid`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "malformed id",
						logrus.ErrorKey:         `spiffeid: unable to parse: parse "spiffe://malformed id": invalid character " " in host name`,
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
				{Status: api.CreateStatus(codes.InvalidArgument, `updating a federated bundle for the server's own trust domain is not allowed`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid argument: updating a federated bundle for the server's own trust domain is not allowed`,
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
					},
				},
			},
		},
		{
			name:            "Update datastore query fails",
			bundlesToUpdate: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			dsError:         errors.New("datastore error"),
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.Internal, `failed to update bundle: datastore error`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to update bundle",
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
				{Status: api.CreateStatus(codes.InvalidArgument, fmt.Sprintf("failed to convert bundle: unable to parse X.509 authority: %v", expectedX509Err))},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         fmt.Sprintf("unable to parse X.509 authority: %v", expectedX509Err),
					},
				},
			},
		},
		{
			name:              "Multiple updates",
			preExistentBundle: &common.Bundle{TrustDomainId: federatedTrustDomain.IDString()},
			bundlesToUpdate:   []*types.Bundle{makeValidBundle(t, spiffeid.RequireTrustDomainFromString("non-existent-td")), makeValidBundle(t, federatedTrustDomain)},
			expectedResults: []*bundlepb.BatchCreateFederatedBundleResponse_Result{
				{
					Status: api.CreateStatus(codes.NotFound, "bundle not found"),
				},
				{
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Bundle not found",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "non-existent-td",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "Federated bundle updated",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			if tt.preExistentBundle != nil {
				_, err := test.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
					Bundle: tt.preExistentBundle,
				})
				require.NoError(t, err)
			}

			test.ds.SetNextError(tt.dsError)
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

				if tt.preExistentBundle != nil {
					// If there was a previous bundle, and the update RPC failed, assert that it didn't change.
					switch codes.Code(result.Status.Code) {
					case codes.OK, codes.NotFound:
					default:
						updatedBundle, err := test.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
							TrustDomainId: "spiffe://" + tt.bundlesToUpdate[i].TrustDomain,
						})
						require.NoError(t, err)
						require.Equal(t, tt.preExistentBundle, updatedBundle.Bundle)
					}
				}
			}
		})
	}
}

func TestBatchSetFederatedBundle(t *testing.T) {
	_, expectedX509Err := x509.ParseCertificates([]byte("malformed"))
	require.Error(t, expectedX509Err)

	updatedBundle := makeValidBundle(t, federatedTrustDomain)
	// Change the refresh hint
	updatedBundle.RefreshHint = 120

	for _, tt := range []struct {
		name            string
		bundlesToSet    []*types.Bundle
		outputMask      *types.BundleMask
		expectedResults []*bundlepb.BatchSetFederatedBundleResponse_Result
		expectedLogMsgs []spiretest.LogEntry
		dsError         error
	}{
		{
			name:         "Succeeds",
			bundlesToSet: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			outputMask: &types.BundleMask{
				RefreshHint: true,
			},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{
					Status: api.OK(),
					Bundle: &types.Bundle{
						TrustDomain: "another-example.org",
						RefreshHint: 60,
					},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle set successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:         "Succeeds with all-false mask",
			bundlesToSet: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			outputMask:   &types.BundleMask{},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{
					Status: api.OK(),
					Bundle: &types.Bundle{TrustDomain: federatedTrustDomain.String()},
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle set successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:         "Succeeds with nil mask",
			bundlesToSet: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: `Bundle set successfully`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name:         "Succeeds if the request has no bundles",
			bundlesToSet: []*types.Bundle{},
		},
		{
			name:         "Updates if bundle already exists",
			bundlesToSet: []*types.Bundle{makeValidBundle(t, federatedTrustDomain), updatedBundle},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{
					Status: api.OK(),
					Bundle: makeValidBundle(t, federatedTrustDomain),
				},
				{
					Status: api.OK(),
					Bundle: updatedBundle,
				},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Bundle set successfully",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "Bundle set successfully",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
					},
				},
			},
		},
		{
			name: "Fails if trust domain is not a valid SPIFFE ID",
			bundlesToSet: []*types.Bundle{
				func() *types.Bundle {
					b := makeValidBundle(t, federatedTrustDomain)
					b.TrustDomain = "//notvalid"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `trust domain argument is not valid: spiffeid: trust domain is empty`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid argument: trust domain argument is not valid`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "//notvalid",
						logrus.ErrorKey:         "spiffeid: trust domain is empty",
					},
				},
			},
		},
		{
			name: "Fails if trust domain is server trust domain",
			bundlesToSet: []*types.Bundle{
				func() *types.Bundle {
					b := makeValidBundle(t, federatedTrustDomain)
					b.TrustDomain = "example.org"
					return b
				}(),
			},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `setting a federated bundle for the server's own trust domain is not allowed`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: `Invalid argument: setting a federated bundle for the server's own trust domain is not allowed`,
					Data: logrus.Fields{
						telemetry.TrustDomainID: "example.org",
					},
				},
			},
		},
		{
			name:         "Datastore error",
			bundlesToSet: []*types.Bundle{makeValidBundle(t, federatedTrustDomain)},
			dsError:      errors.New("datastore error"),
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.Internal, `failed to set bundle: datastore error`)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to set bundle",
					Data: logrus.Fields{
						telemetry.TrustDomainID: "another-example.org",
						logrus.ErrorKey:         "datastore error",
					},
				},
			},
		},
		{
			name: "Malformed bundle",
			bundlesToSet: []*types.Bundle{
				{
					TrustDomain: federatedTrustDomain.String(),
					X509Authorities: []*types.X509Certificate{
						{
							Asn1: []byte("malformed"),
						},
					},
				},
			},
			expectedResults: []*bundlepb.BatchSetFederatedBundleResponse_Result{
				{Status: api.CreateStatus(codes.InvalidArgument, `failed to convert bundle: unable to parse X.509 authority: %v`, expectedX509Err)},
			},
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert bundle",
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
			test := setupServiceTest(t)
			defer test.Cleanup()

			clearDSBundles(t, test.ds)
			test.ds.SetNextError(tt.dsError)

			resp, err := test.client.BatchSetFederatedBundle(context.Background(), &bundlepb.BatchSetFederatedBundleRequest{
				Bundle:     tt.bundlesToSet,
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
		spiretest.RequireProtoListEqual(t, expected.JwtAuthorities, actual.JwtAuthorities)
	} else {
		require.Empty(t, actual.JwtAuthorities)
	}

	if m == nil || m.X509Authorities {
		spiretest.RequireProtoListEqual(t, expected.X509Authorities, actual.X509Authorities)
	} else {
		require.Empty(t, actual.X509Authorities)
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
	client      bundlepb.BundleClient
	ds          *fakedatastore.DataStore
	logHook     *test.Hook
	up          *fakeUpstreamPublisher
	rateLimiter *fakeRateLimiter
	done        func()
	isAdmin     bool
	isAgent     bool
	isLocal     bool
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	ds := fakedatastore.New(t)
	up := new(fakeUpstreamPublisher)
	rateLimiter := new(fakeRateLimiter)
	service := bundle.New(bundle.Config{
		DataStore:         ds,
		TrustDomain:       serverTrustDomain,
		UpstreamPublisher: up,
	})

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	registerFn := func(s *grpc.Server) {
		bundle.RegisterService(s, service)
	}

	test := &serviceTest{
		ds:          ds,
		logHook:     logHook,
		up:          up,
		rateLimiter: rateLimiter,
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

		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
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

type fakeUpstreamPublisher struct {
	t         testing.TB
	err       error
	expectKey *common.PublicKey
}

func (f *fakeUpstreamPublisher) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}

	spiretest.AssertProtoEqual(f.t, f.expectKey, jwtKey)

	return []*common.PublicKey{jwtKey}, nil
}

type fakeRateLimiter struct {
	count int
	err   error
}

func (f *fakeRateLimiter) RateLimit(ctx context.Context, count int) error {
	if f.count != count {
		return fmt.Errorf("rate limiter got %d but expected %d", count, f.count)
	}

	return f.err
}
