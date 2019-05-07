package attestor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/agent/keymanager"
	agentnodeattestor "github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	servernodeattestor "github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentnodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeservernodeattestor"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	testKey, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`))
)

func TestAttestor(t *testing.T) {
	// create CA and server certificates
	caCert := createCACertificate(t)
	serverCert := createServerCertificate(t, caCert)
	agentCert := createAgentCertificate(t, caCert, "/test/foo")

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
		deprecatedAgentID           string
		challengeResponses          []string
		bootstrapBundle             *x509.Certificate
		cachedBundle                []byte
		cachedSVID                  []byte
		joinToken                   string
		err                         string
		omitSVIDUpdate              bool
		overrideSVIDUpdate          *node.X509SVIDUpdate
		storeKey                    crypto.PrivateKey
		failFetchingAttestationData bool
		failAttestCall              bool
	}{
		{
			name: "no bundle available",
			err:  "load bundle: no bundle available",
		},
		{
			name:         "cached bundle empty",
			cachedBundle: []byte(""),
			err:          "load bundle: no certs in bundle",
		},
		{
			name:         "cached bundle malformed",
			cachedBundle: []byte("INVALID DER BYTES"),
			err:          "load bundle: error parsing bundle",
		},
		{
			name:                        "fail fetching attestation data",
			bootstrapBundle:             caCert,
			err:                         "fetching attestation data purposefully failed",
			failFetchingAttestationData: true,
		},
		{
			name:            "response missing svid update",
			bootstrapBundle: caCert,
			omitSVIDUpdate:  true,
			err:             "failed to parse attestation response: missing svid update",
		},
		{
			name:            "response has more than one svid",
			bootstrapBundle: caCert,
			overrideSVIDUpdate: &node.X509SVIDUpdate{
				Svids: map[string]*node.X509SVID{
					"spiffe://domain.test/not/used":      {},
					"spiffe://domain.test/also/not/used": {},
				},
			},
			err: "failed to parse attestation response: expected 1 svid; got 2",
		},
		{
			name:            "response svid has invalid cert chain",
			bootstrapBundle: caCert,
			overrideSVIDUpdate: &node.X509SVIDUpdate{
				Svids: map[string]*node.X509SVID{
					"spiffe://domain.test/not/used": {CertChain: []byte("INVALID")},
				},
			},
			err: "failed to parse attestation response: invalid svid cert chain",
		},
		{
			name:            "response svid has empty cert chain",
			bootstrapBundle: caCert,
			overrideSVIDUpdate: &node.X509SVIDUpdate{
				Svids: map[string]*node.X509SVID{
					"spiffe://domain.test/not/used": {},
				},
			},
			err: "failed to parse attestation response: empty svid cert chain",
		},
		{
			name:            "response missing trust domain bundle",
			bootstrapBundle: caCert,
			overrideSVIDUpdate: &node.X509SVIDUpdate{
				Svids: map[string]*node.X509SVID{
					"spiffe://domain.test/not/used": {CertChain: agentCert.Raw},
				},
			},
			err: "failed to parse attestation response: missing trust domain bundle",
		},
		{
			name:            "response has malformed trust domain bundle",
			bootstrapBundle: caCert,
			overrideSVIDUpdate: &node.X509SVIDUpdate{
				Svids: map[string]*node.X509SVID{
					"spiffe://domain.test/not/used": {CertChain: agentCert.Raw},
				},
				Bundles: map[string]*common.Bundle{
					"spiffe://domain.test": {
						RootCas: []*common.Certificate{
							{DerBytes: []byte("INVALID")},
						},
					},
				},
			},
			err: "failed to parse attestation response: invalid trust domain bundle",
		},
		{
			name:            "success with bootstrap bundle",
			bootstrapBundle: caCert,
		},
		{
			name:         "success with cached bundle",
			cachedBundle: caCert.Raw,
		},
		{
			name:            "success with join token",
			bootstrapBundle: caCert,
			joinToken:       "JOINTOKEN",
		},
		{
			name:              "success with old plugin",
			bootstrapBundle:   caCert,
			deprecatedAgentID: "spiffe://domain.test/spire/agent/test/foo",
		},
		{
			name:              "old plugin returns mismatched SPIFFE ID",
			bootstrapBundle:   caCert,
			deprecatedAgentID: "spiffe://domain.test/spire/agent/test/bar",
			err:               `server returned inconsistent SPIFFE ID: expected "spiffe://domain.test/spire/agent/test/bar"; got "spiffe://domain.test/spire/agent/test/foo"`,
		},
		{
			name:               "success with challenge response",
			bootstrapBundle:    caCert,
			challengeResponses: []string{"FOO", "BAR", "BAZ"},
		},
		{
			name:            "success with cached svid and private key",
			bootstrapBundle: caCert,
			cachedSVID:      agentCert.Raw,
			storeKey:        testKey,
			failAttestCall:  true,
		},
		{
			name:            "malformed cached svid ignored",
			bootstrapBundle: caCert,
			cachedSVID:      []byte("INVALID"),
			storeKey:        testKey,
			failAttestCall:  true,
			err:             "attestation has been purposefully failed",
		},
		{
			name:            "missing key in keymanager ignored",
			bootstrapBundle: caCert,
			cachedSVID:      agentCert.Raw,
			failAttestCall:  true,
			err:             "attestation has been purposefully failed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)

			// prepare the temp directory holding the cached bundle/svid
			dir, err := ioutil.TempDir("", "spire-agent-node-attestor-")
			require.NoError(err)
			svidCachePath := filepath.Join(dir, "svid.der")
			bundleCachePath := filepath.Join(dir, "bundle.der")
			if testCase.cachedBundle != nil {
				writeFile(t, bundleCachePath, testCase.cachedBundle, 0644)
			}
			if testCase.cachedSVID != nil {
				writeFile(t, svidCachePath, testCase.cachedSVID, 0644)
			}

			// load up the fake agent-side node attestor
			var agentNA agentnodeattestor.NodeAttestor
			agentNADone := spiretest.LoadPlugin(t, catalog.MakePlugin("test",
				agentnodeattestor.PluginServer(fakeagentnodeattestor.New(fakeagentnodeattestor.Config{
					Fail:              testCase.failFetchingAttestationData,
					DeprecatedAgentID: testCase.deprecatedAgentID,
					Responses:         testCase.challengeResponses,
				})),
			), &agentNA)
			defer agentNADone()

			// load up the fake server-side node attestor
			var serverNA servernodeattestor.NodeAttestor
			serverNADone := spiretest.LoadPlugin(t, catalog.MakePlugin("test",
				servernodeattestor.PluginServer(fakeservernodeattestor.New("test", fakeservernodeattestor.Config{
					TrustDomain: "domain.test",
					Data: map[string]string{
						"TEST": "foo",
					},
					Challenges: map[string][]string{
						"foo": testCase.challengeResponses,
					},
				})),
			), &serverNA)
			defer serverNADone()

			// load up an in-memory key manager
			var km keymanager.KeyManager
			kmDone := spiretest.LoadPlugin(t, memory.BuiltIn(), &km)
			defer kmDone()
			if testCase.storeKey != nil {
				storePrivateKey(t, km, testCase.storeKey)
			}

			// initialize the catalog
			catalog := fakeagentcatalog.New()
			catalog.SetNodeAttestor(fakeagentcatalog.NodeAttestor("test", agentNA))
			catalog.SetKeyManager(fakeagentcatalog.KeyManager(km))

			// kick off the gRPC server serving the node API
			listener, err := net.Listen("tcp", "localhost:0")
			require.NoError(err)
			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
			node.RegisterNodeServer(server, newFakeNodeAPI(fakeNodeAPIConfig{
				CACert:             caCert,
				Attestor:           serverNA,
				OmitSVIDUpdate:     testCase.omitSVIDUpdate,
				OverrideSVIDUpdate: testCase.overrideSVIDUpdate,
				FailAttestCall:     testCase.failAttestCall,
			}))
			defer server.Stop()
			go server.Serve(listener)

			// create the attestor
			var trustBundle []*x509.Certificate
			if testCase.bootstrapBundle != nil {
				trustBundle = append(trustBundle, testCase.bootstrapBundle)
			}
			log, _ := test.NewNullLogger()
			attestor := New(&Config{
				Catalog:         catalog,
				Metrics:         telemetry.Blackhole{},
				JoinToken:       testCase.joinToken,
				SVIDCachePath:   svidCachePath,
				BundleCachePath: bundleCachePath,
				Log:             log,
				TrustDomain: url.URL{
					Scheme: "spiffe",
					Host:   "domain.test",
				},
				TrustBundle:   trustBundle,
				ServerAddress: listener.Addr().String(),
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
			if testCase.joinToken != "" {
				require.Equal("spiffe://domain.test/spire/agent/join_token/"+testCase.joinToken, result.SVID[0].URIs[0].String())
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

type fakeNodeAPIConfig struct {
	CACert             *x509.Certificate
	Attestor           servernodeattestor.NodeAttestor
	OmitSVIDUpdate     bool
	OverrideSVIDUpdate *node.X509SVIDUpdate
	FailAttestCall     bool
}

type fakeNodeAPI struct {
	node.NodeServer
	c fakeNodeAPIConfig
}

func newFakeNodeAPI(config fakeNodeAPIConfig) *fakeNodeAPI {
	return &fakeNodeAPI{
		c: config,
	}
}

func (n *fakeNodeAPI) Attest(stream node.Node_AttestServer) error {
	// ensure streams are cleaned up
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	attestorStream, err := n.c.Attestor.Attest(ctx)
	if err != nil {
		return err
	}

	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		if n.c.FailAttestCall {
			return errors.New("attestation has been purposefully failed")
		}

		csr, err := x509.ParseCertificateRequest(req.Csr)
		if err != nil {
			return err
		}

		if req.AttestationData.Type == "join_token" {
			resp, err := n.createAttestResponse(csr, idutil.AgentID("domain.test", "/join_token/"+string(req.AttestationData.Data)))
			if err != nil {
				return err
			}

			return stream.Send(resp)
		}

		if err := attestorStream.Send(&servernodeattestor.AttestRequest{
			AttestationData: req.AttestationData,
			Response:        req.Response,
		}); err != nil {
			return err
		}

		attestResp, err := attestorStream.Recv()
		if err != nil {
			return err
		}

		if attestResp.Challenge != nil {
			if err := stream.Send(&node.AttestResponse{
				Challenge: attestResp.Challenge,
			}); err != nil {
				return err
			}
			continue
		}

		resp, err := n.createAttestResponse(csr, attestResp.AgentId)
		if err != nil {
			return err
		}

		return stream.Send(resp)
	}
}

func (n *fakeNodeAPI) createAttestResponse(csr *x509.CertificateRequest, agentID string) (*node.AttestResponse, error) {
	uri, err := idutil.ParseSpiffeID(agentID, idutil.AllowAnyTrustDomainAgent())
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		URIs:         []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, n.c.CACert, csr.PublicKey, testKey)
	if err != nil {
		return nil, err
	}

	svidUpdate := &node.X509SVIDUpdate{
		Svids: map[string]*node.X509SVID{
			agentID: &node.X509SVID{
				CertChain: certDER,
			},
		},
		Bundles: map[string]*common.Bundle{
			"spiffe://domain.test": &common.Bundle{
				TrustDomainId: "spiffe://domain.test",
				RootCas: []*common.Certificate{
					{DerBytes: n.c.CACert.Raw},
				},
			},
		},
	}

	if n.c.OverrideSVIDUpdate != nil {
		svidUpdate = n.c.OverrideSVIDUpdate
	}

	resp := &node.AttestResponse{}
	if !n.c.OmitSVIDUpdate {
		resp.SvidUpdate = svidUpdate
	}

	return resp, nil
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	require.NoError(t, ioutil.WriteFile(path, data, mode))
}

func createCACertificate(t *testing.T) *x509.Certificate {
	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{idutil.TrustDomainURI("domain.test")},
	}
	return createCertificate(t, tmpl, tmpl)
}

func createServerCertificate(t *testing.T, caCert *x509.Certificate) *x509.Certificate {
	tmpl := &x509.Certificate{
		URIs:     []*url.URL{idutil.ServerURI("domain.test")},
		DNSNames: []string{"localhost"},
	}
	return createCertificate(t, tmpl, caCert)
}

func createAgentCertificate(t *testing.T, caCert *x509.Certificate, path string) *x509.Certificate {
	tmpl := &x509.Certificate{
		URIs: []*url.URL{idutil.AgentURI("domain.test", path)},
	}
	return createCertificate(t, tmpl, caCert)
}

func createCertificate(t *testing.T, tmpl, parent *x509.Certificate) *x509.Certificate {
	now := time.Now()
	tmpl.SerialNumber = big.NewInt(0)
	tmpl.NotBefore = now
	tmpl.NotAfter = now.Add(time.Hour)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, testKey.Public(), testKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func storePrivateKey(t *testing.T, km keymanager.KeyManager, privateKey crypto.PrivateKey) {
	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "not an EC key")
	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	_, err = km.StorePrivateKey(context.Background(), &keymanager.StorePrivateKeyRequest{
		PrivateKey: keyBytes,
	})
	require.NoError(t, err)
}
