package attestor_test

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	"github.com/spiffe/spire/pkg/common/telemetry"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	bundlepb "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentnodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeservernodeattestor"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestAttestorWithExperimentalAPI(t *testing.T) {
	// create CA and server certificates
	caCert := createCACertificate(t)
	serverCert := createServerCertificate(t, caCert)
	agentCert := createAgentCertificate(t, caCert, "/test/foo")
	expiredCert := createExpiredCertificate(t, caCert)
	bundle := &types.Bundle{
		TrustDomain:     "domain.test",
		X509Authorities: []*types.X509Certificate{{Asn1: caCert.Raw}},
	}
	svid := &types.X509SVID{
		Id:        &types.SPIFFEID{TrustDomain: "domain.test", Path: "/test/foo"},
		CertChain: [][]byte{agentCert.Raw},
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  testKey,
			},
		},
	}

	testCases := []struct {
		name                        string
		bootstrapBundle             *x509.Certificate
		insecureBootstrap           bool
		cachedBundle                []byte
		cachedSVID                  []byte
		err                         string
		storeKey                    crypto.PrivateKey
		failFetchingAttestationData bool
		agentClient                 *fakeAgentClient
		bundleClient                *fakeBundleClient
	}{
		{
			name:              "insecure bootstrap",
			insecureBootstrap: true,
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:         "cached bundle empty",
			cachedBundle: []byte(""),
			err:          "load bundle: no certs in bundle",
			agentClient: &fakeAgentClient{
				svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
					CertChain: [][]byte{agentCert.Raw},
				},
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:         "cached bundle malformed",
			cachedBundle: []byte("INVALID DER BYTES"),
			err:          "load bundle: error parsing bundle",
			agentClient:  &fakeAgentClient{},
			bundleClient: &fakeBundleClient{},
		},
		{
			name:                        "fail fetching attestation data",
			bootstrapBundle:             caCert,
			err:                         "fetching attestation data purposefully failed",
			failFetchingAttestationData: true,
			agentClient:                 &fakeAgentClient{},
			bundleClient:                &fakeBundleClient{},
		},
		{
			name:            "attest response is missing SVID",
			bootstrapBundle: caCert,
			agentClient:     &fakeAgentClient{},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "failed to parse attestation response: attest response is missing SVID",
		},
		{
			name:            "response SVID has invalid cert chain",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid: &types.X509SVID{CertChain: [][]byte{{11, 22, 33}}},
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "failed to parse attestation response: invalid SVID cert chain",
		},
		{
			name:            "response SVID has empty cert chain",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid: &types.X509SVID{},
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "failed to parse attestation response: empty SVID cert chain",
		},
		{
			name:            "response missing trust domain bundle",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
					CertChain: [][]byte{agentCert.Raw},
				},
			},
			bundleClient: &fakeBundleClient{},
			err:          "failed to get updated bundle: failed to parse trust domain bundle: no bundle provided",
		},
		{
			name:            "response has malformed trust domain bundle",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
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
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:         "success with cached bundle",
			cachedBundle: caCert.Raw,
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:            "success with expired cached bundle",
			bootstrapBundle: caCert,
			cachedSVID:      expiredCert.Raw,
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:            "success with join token",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: "domain.test", Path: "/join_token/JOINTOKEN"},
					CertChain: [][]byte{createAgentCertificate(t, caCert, "/join_token/JOINTOKEN").Raw},
				},
				joinToken: "JOINTOKEN",
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:            "success with challenge response",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid:               svid,
				challengeResponses: []string{"FOO", "BAR", "BAZ"},
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:              "cached svid and private key but missing bundle",
			insecureBootstrap: true,
			cachedSVID:        agentCert.Raw,
			storeKey:          testKey,
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "SVID loaded but no bundle in cache",
		},
		{
			name:         "success with cached svid, private key, and bundle",
			cachedBundle: caCert.Raw,
			cachedSVID:   agentCert.Raw,
			storeKey:     testKey,
			agentClient: &fakeAgentClient{
				svid:            svid,
				failAttestAgent: true,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
		},
		{
			name:            "malformed cached svid ignored",
			bootstrapBundle: caCert,
			cachedSVID:      []byte("INVALID"),
			storeKey:        testKey,
			agentClient: &fakeAgentClient{
				svid:            svid,
				failAttestAgent: true,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "attestation has been purposefully failed",
		},
		{
			name:            "missing key in keymanager ignored",
			bootstrapBundle: caCert,
			cachedSVID:      agentCert.Raw,
			agentClient: &fakeAgentClient{
				svid:            svid,
				failAttestAgent: true,
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "attestation has been purposefully failed",
		},
		{
			name:            "send error",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid:    svid,
				sendErr: errors.New("error in Send"),
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "error in Send",
		},
		{
			name:            "recv error",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid:    svid,
				recvErr: errors.New("error in Recv"),
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "error in Recv",
		},
		{
			name:            "close send error",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid:         svid,
				closeSendErr: errors.New("error in CloseSend"),
			},
			bundleClient: &fakeBundleClient{
				bundle: bundle,
			},
			err: "error in CloseSend",
		},
		{
			name:            "get bundle error",
			bootstrapBundle: caCert,
			agentClient: &fakeAgentClient{
				svid: svid,
			},
			bundleClient: &fakeBundleClient{
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
			svidCachePath, bundleCachePath, removeDir := prepareTestDir(t, testCase.cachedSVID, testCase.cachedBundle)
			defer removeDir()

			// load up the fake agent-side node attestor
			agentNA, agentNADone := prepareAgentNA(t, fakeagentnodeattestor.Config{
				Fail:      testCase.failFetchingAttestationData,
				Responses: testCase.agentClient.challengeResponses,
			})
			defer agentNADone()

			// load up the fake server-side node attestor
			serverNA, serverNADone := prepareServerNA(t, fakeservernodeattestor.Config{
				TrustDomain: "domain.test",
				Data: map[string]string{
					"TEST": "foo",
				},
				Challenges: map[string][]string{
					"foo": testCase.agentClient.challengeResponses,
				},
			})
			defer serverNADone()

			// load up an in-memory key manager
			km, kmDone := prepareKeyManager(t, testCase.storeKey)
			defer kmDone()

			// initialize the catalog
			catalog := fakeagentcatalog.New()
			catalog.SetNodeAttestor(fakeagentcatalog.NodeAttestor("test", agentNA))
			catalog.SetKeyManager(fakeagentcatalog.KeyManager(km))

			// kick off the gRPC server serving the node API
			serverAddr, serverDone := startNodeServer(t, tlsConfig, fakeNodeAPIConfig{
				CACert:         caCert,
				Attestor:       serverNA,
				FailAttestCall: testCase.agentClient.failAttestAgent,
			})
			defer serverDone()

			// create the attestor
			log, _ := test.NewNullLogger()
			attestor := attestor.New(&attestor.Config{
				Catalog:         catalog,
				Metrics:         telemetry.Blackhole{},
				JoinToken:       testCase.agentClient.joinToken,
				SVIDCachePath:   svidCachePath,
				BundleCachePath: bundleCachePath,
				Log:             log,
				TrustDomain: url.URL{
					Scheme: "spiffe",
					Host:   "domain.test",
				},
				TrustBundle:            makeTrustBundle(testCase.bootstrapBundle),
				InsecureBootstrap:      testCase.insecureBootstrap,
				ServerAddress:          serverAddr,
				ExperimentalAPIEnabled: true,
				CreateNewAgentClient:   func(conn grpc.ClientConnInterface) agentpb.AgentClient { return testCase.agentClient },
				CreateNewBundleClient:  func(conn grpc.ClientConnInterface) bundlepb.BundleClient { return testCase.bundleClient },
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
			if testCase.agentClient.joinToken != "" {
				require.Equal("spiffe://domain.test/spire/agent/join_token/"+testCase.agentClient.joinToken, result.SVID[0].URIs[0].String())
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

type fakeAgentClient struct {
	failAttestAgent    bool
	challengeResponses []string
	joinToken          string
	svid               *types.X509SVID
	recvErr            error
	sendErr            error
	closeSendErr       error

	agentpb.AgentClient
}

type fakeBundleClient struct {
	bundle       *types.Bundle
	getBundleErr error

	bundlepb.BundleClient
}

type agentClientStream struct {
	svid               *types.X509SVID
	challengeResponses []string
	joinToken          string
	recvErr            error
	closeSendErr       error
	sendErr            error

	agentpb.Agent_AttestAgentClient
}

func (s *agentClientStream) CloseSend() error {
	return s.closeSendErr
}

func (s *agentClientStream) Send(*agentpb.AttestAgentRequest) error {
	return s.sendErr
}

func (s *agentClientStream) Recv() (*agentpb.AttestAgentResponse, error) {
	if s.recvErr != nil {
		return nil, s.recvErr
	}

	if s.joinToken != "" {
		if s.svid.Id.Path != "/join_token/"+s.joinToken {
			return nil, fmt.Errorf("expected to have path %q", "/join_token/"+s.joinToken)
		}
	}

	if len(s.challengeResponses) > 0 {
		challengeResponse := s.challengeResponses[0]
		s.challengeResponses = s.challengeResponses[1:]
		return &agentpb.AttestAgentResponse{
			Step: &agentpb.AttestAgentResponse_Challenge{
				Challenge: []byte(challengeResponse),
			},
		}, nil
	}

	return &agentpb.AttestAgentResponse{
		Step: &agentpb.AttestAgentResponse_Result_{
			Result: &agentpb.AttestAgentResponse_Result{
				Svid: s.svid,
			},
		},
	}, nil
}

func (c *fakeAgentClient) AttestAgent(ctx context.Context, opts ...grpc.CallOption) (agentpb.Agent_AttestAgentClient, error) {
	if c.failAttestAgent {
		return nil, errors.New("attestation has been purposefully failed")
	}

	return &agentClientStream{
		joinToken:          c.joinToken,
		svid:               c.svid,
		recvErr:            c.recvErr,
		sendErr:            c.sendErr,
		closeSendErr:       c.closeSendErr,
		challengeResponses: c.challengeResponses,
	}, nil
}

func (c *fakeBundleClient) GetBundle(ctx context.Context, in *bundlepb.GetBundleRequest, opts ...grpc.CallOption) (*types.Bundle, error) {
	if c.getBundleErr != nil {
		return nil, c.getBundleErr
	}

	return c.bundle, nil
}
