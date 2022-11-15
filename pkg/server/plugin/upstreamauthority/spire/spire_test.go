package spireplugin

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

type configureCase struct {
	name                     string
	serverAddr               string
	serverPort               string
	workloadAPISocket        string
	workloadAPINamedPipeName string
	overrideCoreConfig       *catalog.CoreConfig
	overrideConfig           string
	expectCode               codes.Code
	expectMsgPrefix          string
	expectServerID           string
	expectWorkloadAPIAddr    net.Addr
	expectServerAddr         string
}

type mintX509CACase struct {
	name                  string
	ttl                   time.Duration
	getCSR                func() ([]byte, crypto.PublicKey)
	expectCode            codes.Code
	expectMsgPrefix       string
	sAPIError             error
	downstreamResp        *svidv1.NewDownstreamX509CAResponse
	customWorkloadAPIAddr net.Addr
	customServerAddr      string
}

func TestConfigure(t *testing.T) {
	cases := []configureCase{
		{
			name:            "malformed configuration",
			overrideConfig:  "{1}",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration: expected: STRING got: NUMBER",
		},
		{
			name:               "no trust domain",
			serverAddr:         "localhost",
			serverPort:         "8081",
			workloadAPISocket:  "socketPath",
			overrideCoreConfig: &catalog.CoreConfig{},
			expectCode:         codes.InvalidArgument,
			expectMsgPrefix:    "trust_domain is required",
		},
	}
	cases = append(cases, configureCasesOS(t)...)
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var err error

			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
			}

			if tt.overrideCoreConfig != nil {
				options = append(options, plugintest.CoreConfig(*tt.overrideCoreConfig))
			} else {
				options = append(options, plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: trustDomain,
				}))
			}

			if tt.overrideConfig != "" {
				options = append(options, plugintest.Configure(tt.overrideConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(Configuration{
					ServerAddr:        tt.serverAddr,
					ServerPort:        tt.serverPort,
					WorkloadAPISocket: tt.workloadAPISocket,
					Experimental: experimentalConfig{
						WorkloadAPINamedPipeName: tt.workloadAPINamedPipeName,
					},
				}))
			}

			p := New()
			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				require.Nil(t, p.serverClient)
				return
			}

			assert.Equal(t, tt.expectServerID, p.serverClient.serverID.String())
			assert.Equal(t, tt.expectWorkloadAPIAddr, p.serverClient.workloadAPIAddr)
			assert.Equal(t, tt.expectServerAddr, p.serverClient.serverAddr)
		})
	}
}

func TestMintX509CA(t *testing.T) {
	ca := testca.New(t, trustDomain)

	// Create SVID returned when fetching
	s := ca.CreateX509SVID(spiffeid.RequireFromPath(trustDomain, "/workload"))
	svidCert, svidKey, err := s.MarshalRaw()
	require.NoError(t, err)

	// Create server's CA
	serverCert, serverKey := ca.CreateX509Certificate(
		testca.WithID(spiffeid.RequireFromPath(trustDomain, "/spire/server")),
	)

	// Create CA for updates
	serverCertUpdate, _ := ca.CreateX509Certificate(
		testca.WithID(spiffeid.RequireFromPath(trustDomain, "/another")),
	)

	csr, pubKey, err := util.NewCSRTemplate(trustDomain.IDString())
	require.NoError(t, err)

	cases := []mintX509CACase{
		{
			name: "valid CSR",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
		},
		{
			name: "invalid server address",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			customServerAddr: "localhost",
			expectCode:       codes.Internal,
			expectMsgPrefix:  `upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp :0`,
		},
		{
			name: "invalid scheme",
			getCSR: func() ([]byte, crypto.PublicKey) {
				csr, pubKey, err := util.NewCSRTemplate("invalid://localhost")
				require.NoError(t, err)
				return csr, pubKey
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: `upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Unknown desc = unable to sign CSR: CSR with SPIFFE ID "invalid://localhost" is invalid: scheme is missing or invalid`,
		},
		{
			name: "wrong trust domain",
			getCSR: func() ([]byte, crypto.PublicKey) {
				csr, pubKey, err := util.NewCSRTemplate("spiffe://not-trusted")
				require.NoError(t, err)
				return csr, pubKey
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: `upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Unknown desc = unable to sign CSR: CSR with SPIFFE ID "spiffe://not-trusted" is invalid: must use the trust domain ID for trust domain "example.org"`,
		},
		{
			name: "invalid CSR",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return []byte("invalid-csr"), nil
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: `upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Unknown desc = unable to sign CSR: unable to parse CSR: asn1: structure error`,
		},
		{
			name: "failed to call server",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			sAPIError:       errors.New("some error"),
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Unknown desc = some error",
		},
		{
			name: "downstream returns malformed X509 authorities",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			downstreamResp: &svidv1.NewDownstreamX509CAResponse{
				X509Authorities: [][]byte{[]byte("malformed")},
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Internal desc = unable to parse X509 authorities: x509: malformed certificate",
		},
		{
			name: "downstream returns malformed CA chain",
			getCSR: func() ([]byte, crypto.PublicKey) {
				return csr, pubKey
			},
			downstreamResp: &svidv1.NewDownstreamX509CAResponse{
				CaCertChain: [][]byte{[]byte("malformed")},
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(spire): unable to request a new Downstream X509CA: rpc error: code = Internal desc = unable to parse CA cert chain: x509: malformed certificate",
		},
	}

	cases = append(cases, mintX509CACasesOS(t)...)
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Setup servers
			server := testHandler{}
			server.startTestServers(t, ca, serverCert, serverKey, svidCert, svidKey)
			server.sAPIServer.setError(c.sAPIError)
			server.sAPIServer.setDownstreamResponse(c.downstreamResp)

			serverAddr := server.sAPIServer.addr
			workloadAPIAddr := server.wAPIServer.workloadAPIAddr
			if c.customServerAddr != "" {
				serverAddr = c.customServerAddr
			}
			if c.customWorkloadAPIAddr != nil {
				workloadAPIAddr = c.customWorkloadAPIAddr
			}

			ua, mockClock := newWithDefault(t, serverAddr, workloadAPIAddr)

			// Send initial request and get stream
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			csr, pubKey := c.getCSR()
			// Get first response
			x509CA, x509Authorities, stream, err := ua.MintX509CA(ctx, csr, c.ttl)

			spiretest.RequireGRPCStatusHasPrefix(t, err, c.expectCode, c.expectMsgPrefix)
			if c.expectCode != codes.OK {
				require.Nil(t, stream)
				require.Nil(t, x509CA)
				require.Nil(t, x509Authorities)
				cancel()
				return
			}

			require.Equal(t, ca.X509Bundle().X509Authorities(), x509Authorities)

			isEqual, err := cryptoutil.PublicKeyEqual(x509CA[0].PublicKey, pubKey)
			require.NoError(t, err)
			require.True(t, isEqual)

			// Verify X509CA has expected IDs
			require.Equal(t, []string{"spiffe://example.org"}, certChainURIs(x509CA))

			// Update bundle to trigger another response. Move time forward at
			// the upstream poll frequency twice to ensure the plugin picks up
			// the change to the bundle.
			server.sAPIServer.appendRootCA(&types.X509Certificate{Asn1: serverCertUpdate[0].Raw})
			mockClock.Add(upstreamPollFreq)
			mockClock.Add(upstreamPollFreq)
			mockClock.Add(internalPollFreq)

			// Get bundle update
			bundleUpdateResp, err := stream.RecvUpstreamX509Authorities()
			require.NoError(t, err)

			expectBundles := append(ca.X509Authorities(), serverCertUpdate...)
			require.Equal(t, expectBundles, bundleUpdateResp)

			// Cancel ctx to stop getting updates
			cancel()

			// Verify stream is closed
			resp, err := stream.RecvUpstreamX509Authorities()
			spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Canceled, "upstreamauthority(spire): context canceled")
			require.Nil(t, resp)
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	ca := testca.New(t, trustDomain)
	serverCert, serverKey := ca.CreateX509Certificate(
		testca.WithID(spiffeid.RequireFromPath(trustDomain, "/spire/server")),
	)
	s := ca.CreateX509SVID(
		spiffeid.RequireFromPath(trustDomain, "/workload"),
	)
	svidCert, svidKey, err := s.MarshalRaw()
	require.NoError(t, err)

	key := testkey.NewEC256(t)
	pkixBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	key2 := testkey.NewEC256(t)
	pkixBytes2, err := x509.MarshalPKIXPublicKey(key2.Public())
	require.NoError(t, err)

	// Setup servers
	server := testHandler{}
	server.startTestServers(t, ca, serverCert, serverKey, svidCert, svidKey)
	ua, mockClock := newWithDefault(t, server.sAPIServer.addr, server.wAPIServer.workloadAPIAddr)

	// Get first response
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upstreamJwtKeys, stream, err := ua.PublishJWTKey(ctx, &common.PublicKey{
		Kid:       "kid-2",
		PkixBytes: pkixBytes,
	})
	require.NoError(t, err)
	require.NotNil(t, stream)
	require.NotNil(t, upstreamJwtKeys)

	require.Len(t, upstreamJwtKeys, 3)
	assert.Equal(t, upstreamJwtKeys[0].Kid, "C6vs25welZOx6WksNYfbMfiw9l96pMnD")
	assert.Equal(t, upstreamJwtKeys[1].Kid, "gHTCunJbefYtnZnTctd84xeRWyMrEsWD")
	assert.Equal(t, upstreamJwtKeys[2].Kid, "kid-2")

	// Update bundle to trigger another response. Move time forward at the
	// upstream poll frequency twice to ensure the plugin picks up the change
	// to the bundle.
	server.sAPIServer.appendKey(&types.JWTKey{KeyId: "kid-3", PublicKey: pkixBytes2})
	mockClock.Add(upstreamPollFreq)
	mockClock.Add(upstreamPollFreq)
	mockClock.Add(internalPollFreq)

	// Get bundle update
	resp, err := stream.RecvUpstreamJWTAuthorities()
	require.NoError(t, err)
	require.Len(t, resp, 4)
	require.Equal(t, resp[3].Kid, "kid-3")
	require.Equal(t, resp[3].PkixBytes, pkixBytes2)

	// Cancel ctx to stop getting updates
	cancel()

	// Verify stream is closed
	resp, err = stream.RecvUpstreamJWTAuthorities()
	require.Nil(t, resp)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Canceled, "upstreamauthority(spire): context canceled")

	// Fail to push JWT authority
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.sAPIServer.setError(errors.New("some error"))
	upstreamJwtKeys, _, err = ua.PublishJWTKey(ctx, &common.PublicKey{
		Kid:       "kid-2",
		PkixBytes: pkixBytes,
	})
	require.Nil(t, upstreamJwtKeys)
	spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "upstreamauthority(spire): failed to push JWT authority: rpc error: code = Unknown desc = some erro")
}

func newWithDefault(t *testing.T, serverAddr string, workloadAPIAddr net.Addr) (*upstreamauthority.V1, *clock.Mock) {
	host, port, _ := net.SplitHostPort(serverAddr)
	config := Configuration{
		ServerAddr: host,
		ServerPort: port,
	}
	setWorkloadAPIAddr(&config, workloadAPIAddr)

	ua := new(upstreamauthority.V1)
	plugintest.Load(t, BuiltIn(), ua,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: trustDomain,
		}),
		plugintest.ConfigureJSON(config),
	)

	mockClock := clock.NewMock(t)

	clk = mockClock

	return ua, mockClock
}

func certChainURIs(chain []*x509.Certificate) []string {
	var uris []string
	for _, cert := range chain {
		uris = append(uris, certURI(cert))
	}
	return uris
}

func certURI(cert *x509.Certificate) string {
	if len(cert.URIs) == 1 {
		return cert.URIs[0].String()
	}
	return ""
}
