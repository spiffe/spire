package attestor_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/fakes/fakeagentnodeattestor"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	caKey       = testkey.MustEC256()
	serverKey   = testkey.MustEC256()
	trustDomain = spiffeid.RequireTrustDomainFromString("domain.test")
)

func TestAttestor(t *testing.T) {
	km := fakeagentkeymanager.New(t, "")

	agentKey, err := keymanager.ForSVID(km).GenerateKey(context.Background(), nil)
	require.NoError(t, err)

	// create CA and server certificates
	caCert := createCACertificate(t)
	serverCert := createServerCertificate(t, caCert)
	agentCert := createAgentCertificate(t, caCert, agentKey, "/test/foo")
	expiredCert := createExpiredCertificate(t, caCert, agentKey)
	bundle := &types.Bundle{
		TrustDomain:     trustDomain.String(),
		X509Authorities: []*types.X509Certificate{{Asn1: caCert.Raw}},
	}
	svid := &types.X509SVID{
		Id:        &types.SPIFFEID{TrustDomain: trustDomain.String(), Path: "/test/foo"},
		CertChain: [][]byte{agentCert.Raw},
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
			},
		},
		MinVersion: tls.VersionTLS12,
	}

	testCases := []struct {
		name                        string
		bootstrapBundle             *x509.Certificate
		insecureBootstrap           bool
		cachedBundle                []byte
		cachedSVID                  []byte
		err                         string
		keepAgentKey                bool
		failFetchingAttestationData bool
		agentService                *fakeAgentService
		bundleService               *fakeBundleService
	}{
		{
			name:              "insecure bootstrap",
			insecureBootstrap: true,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:         "cached bundle empty",
			cachedBundle: []byte(""),
			err:          "load bundle: no certs in bundle",
			agentService: &fakeAgentService{
				svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
					CertChain: [][]byte{agentCert.Raw},
				},
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:          "cached bundle malformed",
			cachedBundle:  []byte("INVALID DER BYTES"),
			err:           "load bundle: error parsing bundle",
			agentService:  &fakeAgentService{},
			bundleService: &fakeBundleService{bundle: &types.Bundle{}},
		},
		{
			name:                        "fail fetching attestation data",
			bootstrapBundle:             caCert,
			err:                         "fetching attestation data failed by test",
			failFetchingAttestationData: true,
			agentService:                &fakeAgentService{},
			bundleService:               &fakeBundleService{},
		},
		{
			name:            "attest response is missing SVID",
			bootstrapBundle: caCert,
			agentService:    &fakeAgentService{},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
			err: "failed to parse attestation response: attest response is missing SVID",
		},
		{
			name:            "response SVID has invalid cert chain",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid: &types.X509SVID{CertChain: [][]byte{{11, 22, 33}}},
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
			err: "failed to parse attestation response: invalid SVID cert chain",
		},
		{
			name:            "response SVID has empty cert chain",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid: &types.X509SVID{},
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
			err: "failed to parse attestation response: empty SVID cert chain",
		},
		{
			name:            "response has malformed trust domain bundle",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				bundle: &types.Bundle{
					TrustDomain:     "spiffe://example.org",
					X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
				},
			},
			err: "failed to get updated bundle: invalid trust domain bundle: unable to parse root CA",
		},
		{
			name:            "success with bootstrap bundle",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:         "success with cached bundle",
			cachedBundle: caCert.Raw,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:            "success with expired cached bundle",
			bootstrapBundle: caCert,
			cachedSVID:      expiredCert.Raw,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:            "success with join token",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: trustDomain.String(), Path: "/join_token/JOINTOKEN"},
					CertChain: [][]byte{createAgentCertificate(t, caCert, agentKey, "/join_token/JOINTOKEN").Raw},
				},
				joinToken: "JOINTOKEN",
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:            "success with challenge response",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid:               svid,
				challengeResponses: []string{"FOO", "BAR", "BAZ"},
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:              "cached svid and private key but missing bundle",
			insecureBootstrap: true,
			cachedSVID:        agentCert.Raw,
			keepAgentKey:      true,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
			err: "SVID loaded but no bundle in cache",
		},
		{
			name:         "success with cached svid, private key, and bundle",
			cachedBundle: caCert.Raw,
			cachedSVID:   agentCert.Raw,
			keepAgentKey: true,
			agentService: &fakeAgentService{
				svid:            svid,
				failAttestAgent: true,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
		},
		{
			name:            "malformed cached svid ignored",
			bootstrapBundle: caCert,
			cachedSVID:      []byte("INVALID"),
			keepAgentKey:    true,
			agentService: &fakeAgentService{
				svid:            svid,
				failAttestAgent: true,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
			err: "attestation failed by test",
		},
		{
			name:            "missing key in keymanager ignored",
			bootstrapBundle: caCert,
			cachedSVID:      agentCert.Raw,
			agentService: &fakeAgentService{
				svid:            svid,
				failAttestAgent: true,
			},
			bundleService: &fakeBundleService{
				bundle: bundle,
			},
			err: "attestation failed by test",
		},
		{
			name:            "get bundle error",
			bootstrapBundle: caCert,
			agentService: &fakeAgentService{
				svid: svid,
			},
			bundleService: &fakeBundleService{
				getBundleErr: errors.New("error in GetBundle"),
			},
			err: "error in GetBundle",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)

			// prepare the temp directory holding the cached bundle/svid
			svidCachePath, bundleCachePath := prepareTestDir(t, testCase.cachedSVID, testCase.cachedBundle)

			// load up the fake agent-side node attestor
			agentNA := fakeagentnodeattestor.New(t, fakeagentnodeattestor.Config{
				Fail:      testCase.failFetchingAttestationData,
				Responses: testCase.agentService.challengeResponses,
			})

			// initialize the catalog
			catalog := fakeagentcatalog.New()
			catalog.SetNodeAttestor(agentNA)
			catalog.SetKeyManager(km)

			// Set a pristine km in the catalog if we're not keeping the agent
			// key
			if !testCase.keepAgentKey {
				catalog.SetKeyManager(fakeagentkeymanager.New(t, ""))
			}

			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
			agentv1.RegisterAgentServer(server, testCase.agentService)
			bundlev1.RegisterBundleServer(server, testCase.bundleService)

			listener, err := net.Listen("tcp", "localhost:0")
			require.NoError(err)
			t.Cleanup(func() { listener.Close() })

			spiretest.ServeGRPCServerOnListener(t, server, listener)

			// create the attestor
			log, _ := test.NewNullLogger()
			attestor := attestor.New(&attestor.Config{
				Catalog:           catalog,
				Metrics:           telemetry.Blackhole{},
				JoinToken:         testCase.agentService.joinToken,
				SVIDCachePath:     svidCachePath,
				BundleCachePath:   bundleCachePath,
				Log:               log,
				TrustDomain:       trustDomain,
				TrustBundle:       makeTrustBundle(testCase.bootstrapBundle),
				InsecureBootstrap: testCase.insecureBootstrap,
				ServerAddress:     listener.Addr().String(),
			})

			// perform attestation
			result, err := attestor.Attest(context.Background())
			if testCase.err != "" {
				spiretest.RequireErrorContains(t, err, testCase.err)
				return
			}
			require.NoError(err)
			require.NotNil(result)
			require.Len(result.SVID, 1)
			require.Len(result.SVID[0].URIs, 1)
			if testCase.agentService.joinToken != "" {
				require.Equal("spiffe://domain.test/spire/agent/join_token/"+testCase.agentService.joinToken, result.SVID[0].URIs[0].String())
			} else {
				require.Equal("spiffe://domain.test/spire/agent/test/foo", result.SVID[0].URIs[0].String())
			}
			require.NotNil(result.Key)
			require.NotNil(result.Bundle)

			rootCAs := result.Bundle.RootCAs()
			require.Len(rootCAs, 1)
			require.Equal(rootCAs[0].Raw, caCert.Raw)
		})
	}
}

type fakeAgentService struct {
	failAttestAgent    bool
	challengeResponses []string
	joinToken          string
	svid               *types.X509SVID

	agentv1.AgentServer
}

func (s *fakeAgentService) AttestAgent(stream agentv1.Agent_AttestAgentServer) error {
	_, err := stream.Recv()
	if err != nil {
		return err
	}

	if s.failAttestAgent {
		return errors.New("attestation failed by test")
	}

	if s.joinToken != "" {
		if s.svid.Id.Path != "/join_token/"+s.joinToken {
			return fmt.Errorf("expected to have path %q", "/join_token/"+s.joinToken)
		}
	}

	for len(s.challengeResponses) > 0 {
		challengeResponse := s.challengeResponses[0]
		s.challengeResponses = s.challengeResponses[1:]
		if err := stream.Send(&agentv1.AttestAgentResponse{
			Step: &agentv1.AttestAgentResponse_Challenge{
				Challenge: []byte(challengeResponse),
			},
		}); err != nil {
			return err
		}

		_, err = stream.Recv()
		if err != nil {
			return err
		}
	}

	return stream.Send(&agentv1.AttestAgentResponse{
		Step: &agentv1.AttestAgentResponse_Result_{
			Result: &agentv1.AttestAgentResponse_Result{
				Svid: s.svid,
			},
		},
	})
}

type fakeBundleService struct {
	bundle       *types.Bundle
	getBundleErr error

	bundlev1.BundleServer
}

func (c *fakeBundleService) GetBundle(ctx context.Context, in *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	if c.getBundleErr != nil {
		return nil, c.getBundleErr
	}

	return c.bundle, nil
}

func prepareTestDir(t *testing.T, cachedSVID, cachedBundle []byte) (string, string) {
	dir := spiretest.TempDir(t)

	svidCachePath := filepath.Join(dir, "svid.der")
	bundleCachePath := filepath.Join(dir, "bundle.der")
	if cachedSVID != nil {
		writeFile(t, svidCachePath, cachedSVID, 0644)
	}
	if cachedBundle != nil {
		writeFile(t, bundleCachePath, cachedBundle, 0644)
	}

	return svidCachePath, bundleCachePath
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	require.NoError(t, os.WriteFile(path, data, mode))
}

func createCACertificate(t *testing.T) *x509.Certificate {
	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{idutil.TrustDomainURI(trustDomain.String())},
	}
	return createCertificate(t, tmpl, tmpl, caKey, caKey)
}

func createServerCertificate(t *testing.T, caCert *x509.Certificate) *x509.Certificate {
	tmpl := &x509.Certificate{
		URIs:     []*url.URL{idutil.ServerID(trustDomain).URL()},
		DNSNames: []string{"localhost"},
	}
	return createCertificate(t, tmpl, caCert, serverKey, caKey)
}

func createAgentCertificate(t *testing.T, caCert *x509.Certificate, agentKey crypto.Signer, path string) *x509.Certificate {
	tmpl := &x509.Certificate{
		URIs: []*url.URL{idutil.AgentURI(trustDomain.String(), path)},
	}
	return createCertificate(t, tmpl, caCert, agentKey, caKey)
}

func createExpiredCertificate(t *testing.T, caCert *x509.Certificate, agentKey crypto.Signer) *x509.Certificate {
	tmpl := &x509.Certificate{
		NotAfter: time.Now().Add(-1 * time.Hour),
		URIs:     []*url.URL{idutil.AgentURI(trustDomain.String(), "/test/expired")},
	}
	return createCertificate(t, tmpl, caCert, agentKey, caKey)
}

func createCertificate(t *testing.T, tmpl, parent *x509.Certificate, certKey, parentKey crypto.Signer) *x509.Certificate {
	now := time.Now()
	tmpl.SerialNumber = big.NewInt(0)
	tmpl.NotBefore = now
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = now.Add(time.Hour)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, certKey.Public(), parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func makeTrustBundle(bootstrapCert *x509.Certificate) []*x509.Certificate {
	var trustBundle []*x509.Certificate
	if bootstrapCert != nil {
		trustBundle = append(trustBundle, bootstrapCert)
	}
	return trustBundle
}

func TestIsSVIDExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		Desc          string
		SVID          []*x509.Certificate
		ExpectExpired bool
	}{
		{
			Desc: "cert expiration is in the past",
			SVID: []*x509.Certificate{
				{NotAfter: now.Add(-2 * time.Second)},
			},
			ExpectExpired: true,
		},
		{
			Desc: "cert is about to expire",
			SVID: []*x509.Certificate{
				{NotAfter: now.Add(time.Second)},
			},
			ExpectExpired: true,
		},
		{
			Desc: "cert expiration is safely in the future",
			SVID: []*x509.Certificate{
				{NotAfter: now.Add(time.Minute)},
			},
			ExpectExpired: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Desc, func(t *testing.T) {
			isExpired := attestor.IsSVIDExpired(tt.SVID, func() time.Time { return now })
			require.Equal(t, tt.ExpectExpired, isExpired)
		})
	}
}
