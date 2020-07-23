package node

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/pkg/server/util/regentryutil"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakenoderesolver"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeservernodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeupstreamauthority"
	"github.com/spiffe/spire/test/spiretest"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	trustDomain   = "example.org"
	trustDomainID = "spiffe://example.org"

	otherDomainID = "spiffe://otherdomain.test"

	serverID     = "spiffe://example.org/spire/server"
	agentID      = "spiffe://example.org/spire/agent/test/id"
	downstreamID = "spiffe://example.org/downstream"
	workloadID   = "spiffe://example.org/workload"
	joinTokenID  = "spiffe://example.org/spire/agent/join_token/TOKEN" //nolint: gosec // false positive

	// used to cancel stream operations on test failure instead of blocking the
	// full go test timeout period (i.e. 10 minutes)
	testTimeout = time.Minute
)

var (
	trustDomainURL, _ = idutil.ParseSpiffeID(trustDomainID, idutil.AllowAnyTrustDomain())

	otherDomainBundle = &common.Bundle{
		TrustDomainId: otherDomainID,
	}

	irrelevantSelectors = []*common.Selector{{Type: "not", Value: "relevant"}}

	testKey, _ = pemutil.ParseECPrivateKey([]byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUdF3LNDNZWKYQHFj
UIs5TNt4LXDawuZFFj2J7D1T9mehRANCAASEhjkDbIFdNaZ9EneJaSXKfLiBDqt2
l37cUGNqRvIYDhSH/IJycqxLTtvHoYMHLSV9N5UHIFgPJ/30RCBQiH3t
-----END PRIVATE KEY-----
`))

	jwtSigningKey, _ = pemutil.ParseSigner([]byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGZx/yLVskGyXAyIT
uDe7PI1X4Dt1boMWfysKPyOJeMuhRANCAARzgo1R4J4xtjGpmGFNl2KADaxDpgx3
KfDQqPUcYWUMm2JbwFyHxQfhJfSf+Mla5C4FnJG6Ksa7pWjITPf5KbHi
-----END PRIVATE KEY-----
`))
)

func TestHandler(t *testing.T) {
	spiretest.Run(t, new(HandlerSuite))
}

type HandlerSuite struct {
	spiretest.Suite

	server                        *grpc.Server
	logHook                       *test.Hook
	limiter                       *fakeLimiter
	handler                       *Handler
	metrics                       *fakemetrics.FakeMetrics
	expectedMetrics               *fakemetrics.FakeMetrics
	unattestedClient              node.NodeClient
	attestedClient                node.NodeClient
	ds                            *fakedatastore.DataStore
	catalog                       *fakeservercatalog.Catalog
	clock                         *clock.Mock
	bundle                        *common.Bundle
	agentSVID                     []*x509.Certificate
	downstreamSVID                []*x509.Certificate
	workloadSVID                  []*x509.Certificate
	serverCA                      *fakeserverca.CA
	fetchRegistrationEntriesCache *regentryutil.FetchRegistrationEntriesCache
}

func (s *HandlerSuite) SetupTest() {
	s.setupTest(nil)
}

func (s *HandlerSuite) setupTest(upstreamAuthorityConfig *fakeupstreamauthority.Config) {
	s.clock = clock.NewMock(s.T())

	log, logHook := test.NewNullLogger()
	s.logHook = logHook

	s.limiter = new(fakeLimiter)

	s.ds = fakedatastore.New(s.T())
	s.catalog = fakeservercatalog.New()
	s.catalog.SetDataStore(s.ds)
	if upstreamAuthorityConfig != nil {
		upstreamAuthority, _, uaDone := fakeupstreamauthority.Load(s.T(), *upstreamAuthorityConfig)
		s.AppendCloser(uaDone)
		s.catalog.SetUpstreamAuthority(fakeservercatalog.UpstreamAuthority(
			"fakeupstreamauthority",
			upstreamAuthority,
		))
	}

	s.serverCA = fakeserverca.New(s.T(), trustDomain, &fakeserverca.Options{
		Clock: s.clock,
	})
	s.bundle = bundleutil.BundleProtoFromRootCAs(trustDomainID, s.serverCA.Bundle())

	s.createBundle(s.bundle)

	// Create server and agent SVIDs for TLS communication
	serverSVID := s.makeSVID(serverID)
	s.agentSVID = s.makeSVID(agentID)
	s.downstreamSVID = s.makeSVID(downstreamID)
	s.workloadSVID = s.makeSVID(workloadID)

	s.metrics = fakemetrics.New()
	s.expectedMetrics = fakemetrics.New()

	handler, err := NewHandler(HandlerConfig{
		Log:         log,
		Metrics:     s.metrics,
		Catalog:     s.catalog,
		ServerCA:    s.serverCA,
		TrustDomain: *trustDomainURL,
		Clock:       s.clock,
		Manager: ca.NewManager(ca.ManagerConfig{
			Catalog:     s.catalog,
			TrustDomain: *trustDomainURL,
			Log:         log,
		}),
	})
	s.Require().NoError(err)
	handler.limiter = s.limiter
	cache, err := lru.New(100)
	s.Require().NoError(err)
	s.fetchRegistrationEntriesCache = &regentryutil.FetchRegistrationEntriesCache{
		Cache:   cache,
		TimeNow: s.clock.Now,
	}
	handler.fetchRegistrationEntriesCache = s.fetchRegistrationEntriesCache

	// Streaming methods and auth are easier to test from the client point of view.
	// TODO: share the setup done by the "endpoints" code so these don't go out
	// of sync.
	rootCAs := x509.NewCertPool()
	for _, bundleCert := range s.serverCA.Bundle() {
		rootCAs.AddCert(bundleCert)
	}
	var tlsCertificate [][]byte
	for _, serverCert := range serverSVID {
		tlsCertificate = append(tlsCertificate, serverCert.Raw)
	}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(auth.UnaryAuthorizeCall),
		grpc.StreamInterceptor(auth.StreamAuthorizeCall),
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: tlsCertificate,
					PrivateKey:  testKey,
				},
			},
			ClientCAs:  rootCAs,
			ClientAuth: tls.VerifyClientCertIfGiven,
		})))
	node.RegisterNodeServer(server, handler)

	listener, err := net.Listen("tcp", "localhost:0")
	s.Require().NoError(err)
	go func() { _ = server.Serve(listener) }()

	unattestedConn, err := grpc.Dial(listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			// skip verification of the server certificate. otherwise we'd
			// need SANs to allow the connection over localhost. this isn't
			// important for these tests.
			InsecureSkipVerify: true, //nolint: gosec
		})))
	s.Require().NoError(err)

	attestedConn, err := grpc.Dial(listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			// skip verification of the server certificate. otherwise we'd
			// need SANs to allow the connection over localhost. this isn't
			// important for these tests.
			InsecureSkipVerify:   true, //nolint: gosec
			GetClientCertificate: s.getClientCertificate,
		})))
	s.Require().NoError(err)

	s.handler = handler
	s.server = server
	s.unattestedClient = node.NewNodeClient(unattestedConn)
	s.attestedClient = node.NewNodeClient(attestedConn)
}

func (s *HandlerSuite) TearDownTest() {
	s.server.Stop()
}

func (s *HandlerSuite) TestAttestLimits() {
	s.limiter.setNextError(errors.New("limit exceeded"))
	s.requireAttestFailure(&node.AttestRequest{},
		codes.ResourceExhausted, "limit exceeded")
	// Attest always adds 1 count
	s.Equal(1, s.limiter.callsFor(AttestMsg))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNoAttestationData() {
	s.requireAttestFailure(&node.AttestRequest{},
		codes.InvalidArgument, "request missing attestation data")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNoAttestationDataType() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: &common.AttestationData{},
	}, codes.InvalidArgument, "request missing attestation data type")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNoCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
	}, codes.InvalidArgument, "request missing CSR")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithMalformedCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             []byte("MALFORMED"),
	}, codes.InvalidArgument, "request CSR is invalid: failed to parse CSR")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithAgentIDFromWrongTrustDomainInCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR("spiffe://otherdomain.test/spire/agent/test/id"),
	}, codes.InvalidArgument, `request CSR is invalid: invalid SPIFFE ID in CSR: "spiffe://otherdomain.test/spire/agent/test/id" does not belong to trust domain`)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNonAgentIDInCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR("spiffe://example.org"),
	}, codes.InvalidArgument, `request CSR is invalid: invalid SPIFFE ID in CSR: "spiffe://example.org" is not a valid agent SPIFFE ID: path is empty`)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithUnknownAttestor() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR(agentID),
	}, codes.Unimplemented, `could not find node attestor type "test"`)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithMismatchedAgentIDWithDeprecatedCSR() {
	s.addAttestor(fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
	})

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR("spiffe://example.org/spire/agent/test/other"),
	}, codes.NotFound, "attestor returned unexpected response")

	s.assertLastLogMessage("Attested SPIFFE ID does not match CSR")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestSuccess() {
	s.testAttestSuccess(s.makeCSRWithoutURISAN())

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestSuccessWithDeprecatedCSR() {
	s.testAttestSuccess(s.makeCSR(agentID))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) testAttestSuccess(csr []byte) {
	// Create a federated bundle to return with the SVID update
	s.createBundle(otherDomainBundle)

	// Create a registration entry to return with the SVID update
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:      agentID,
		SpiffeId:      workloadID,
		Selectors:     irrelevantSelectors,
		FederatesWith: []string{otherDomainID},
	})

	s.addAttestor(fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
	})

	upd := s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             csr,
	}, agentID)

	// assert update contents
	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd, otherDomainBundle)
	svidChain := s.assertSVIDsInUpdate(upd, map[string]string{agentID: agentID})[0]

	// Assert an attested node entry has been created
	attestedNode := s.fetchAttestedNode()
	s.Require().NotNil(attestedNode)
	s.Equal("test", attestedNode.AttestationDataType)
	s.Equal(agentID, attestedNode.SpiffeId)
	s.Equal(svidChain[0].SerialNumber.String(), attestedNode.CertSerialNumber)
	s.WithinDuration(svidChain[0].NotAfter, time.Unix(attestedNode.CertNotAfter, 0), 0)

	// No selectors were returned and no resolvers were available, so the node
	// selectors should be empty.
	s.Empty(s.getNodeSelectors())
}

func (s *HandlerSuite) TestAttestAgentless() {
	attestor := fakeservernodeattestor.Config{
		Data:          map[string]string{"data": workloadID},
		ReturnLiteral: true,
	}

	agentlessCSR := s.makeCSR(workloadID)

	// By default "/spire/agent/* is expected for attestation calls
	s.addAttestor(attestor)
	s.False(s.handler.c.AllowAgentlessNodeAttestors)
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             agentlessCSR,
	}, codes.InvalidArgument, "expecting \"/spire/agent/*\"")

	// If allow agentless is enabled attestation will run successfully
	s.handler.c.AllowAgentlessNodeAttestors = true
	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             agentlessCSR,
	}, workloadID)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestReattestation() {
	// Make sure reattestation is allowed by the attestor
	s.addAttestor(fakeservernodeattestor.Config{
		//CanReattest: true,
		Data: map[string]string{"data": "id"},
	})

	// Create an attested node entry
	initialSerialNumber := "111"
	initialNotAfter := time.Now().Add(time.Hour).Unix()
	s.createAttestedNode(&common.AttestedNode{
		SpiffeId:         agentID,
		CertSerialNumber: initialSerialNumber,
		CertNotAfter:     initialNotAfter,
	})

	// Reattest
	resp := s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID)

	// Assert the attested node entry has been updated
	attestedNode := s.fetchAttestedNode()
	s.Require().NotNil(attestedNode)
	s.Equal(agentID, attestedNode.SpiffeId)

	// Current serial and expiration must be updated
	cert, err := x509.ParseCertificate(resp.Svids[agentID].CertChain)
	s.Require().NoError(err)
	s.Equal(cert.SerialNumber.String(), attestedNode.CertSerialNumber)
	s.Equal(resp.Svids[agentID].ExpiresAt, attestedNode.CertNotAfter)

	// New serial and expiration must be zero-valued
	s.Zero(attestedNode.NewCertSerialNumber)
	s.Zero(attestedNode.NewCertNotAfter)

	// Attestation data type is NOT updatable
	s.Equal("", attestedNode.AttestationDataType)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())

	// Request validation must succeed
	s.NoError(s.handler.validateAgentSVID(context.Background(), cert))
	nodeAfterValidation := s.fetchAttestedNode()

	// There must not be any expected change in the node after request validation
	s.Equal(nodeAfterValidation.CertSerialNumber, attestedNode.CertSerialNumber)
	s.Equal(nodeAfterValidation.CertNotAfter, attestedNode.CertNotAfter)
	s.Zero(nodeAfterValidation.NewCertSerialNumber)
	s.Zero(nodeAfterValidation.NewCertNotAfter)
}

func (s *HandlerSuite) TestAttestChallengeResponseSuccess() {
	// Make sure reattestation is allowed by the attestor
	s.addAttestor(fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
		Challenges: map[string][]string{
			"id": {"one", "two", "three"},
		},
	})

	// Attest via challenge response
	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID, "one", "two", "three")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithUnknownJoinToken() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: &common.AttestationData{Type: "join_token", Data: []byte("TOKEN")},
		Csr:             s.makeCSR(joinTokenID),
	}, codes.Unknown, "failed to attest: no such token")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithAlreadyUsedJoinToken() {
	s.createAttestedNode(&common.AttestedNode{
		SpiffeId: joinTokenID,
	})

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: &common.AttestationData{Type: "join_token", Data: []byte("TOKEN")},
		Csr:             s.makeCSR(joinTokenID),
	}, codes.Unknown, "failed to attest: join token has already been used")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithExpiredJoinToken() {
	s.createJoinToken("TOKEN", s.clock.Now().Add(-time.Second))

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("join_token", "TOKEN"),
		Csr:             s.makeCSR(joinTokenID),
	}, codes.Unknown, "failed to attest: join token expired")

	// join token should be removed from the datastore even if attestation failed
	s.Nil(s.fetchJoinToken("TOKEN"))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithValidJoinToken() {
	s.createJoinToken("TOKEN", s.clock.Now().Add(time.Second))
	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("join_token", "TOKEN"),
		Csr:             s.makeCSR(joinTokenID),
	}, joinTokenID)

	// join token should be removed for successful attestation
	s.Nil(s.fetchJoinToken("TOKEN"))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithOnlyAttestorSelectors() {
	// configure the attestor to return selectors
	s.addAttestor(fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
		Selectors: map[string][]string{
			"id": {"test-attestor-value"},
		},
	})

	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID)

	s.Equal([]*common.Selector{
		{Type: "test", Value: "test-attestor-value"},
	}, s.getNodeSelectors())

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithOnlyResolverSelectors() {
	// configure the attestor to return selectors
	s.addAttestor(fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
	})

	// this resolver does not match the attestor type and should be ignored
	s.addResolver("other", fakenoderesolver.Config{
		Selectors: map[string][]string{
			agentID: {"other-resolver-value"},
		},
	})

	// this resolver matches the attestor type and should be used
	s.addResolver("test", fakenoderesolver.Config{
		Selectors: map[string][]string{
			agentID: {"test-resolver-value"},
		},
	})

	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID)

	s.Equal([]*common.Selector{
		{Type: "test", Value: "test-resolver-value"},
	}, s.getNodeSelectors())

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithBothAttestorAndResolverSelectors() {
	// configure the attestor to return selectors
	s.addAttestor(fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
		Selectors: map[string][]string{
			"id": {"test-attestor-value"},
		},
	})

	s.addResolver("test", fakenoderesolver.Config{
		Selectors: map[string][]string{
			agentID: {"test-resolver-value"},
		},
	})

	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID)

	s.ElementsMatch([]*common.Selector{
		{Type: "test", Value: "test-attestor-value"},
		{Type: "test", Value: "test-resolver-value"},
	}, s.getNodeSelectors())

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestBannedAgent() {
	attestor := fakeservernodeattestor.Config{
		Data:          map[string]string{"data": agentID},
		ReturnLiteral: true,
	}

	s.addAttestor(attestor)
	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID)

	// Ban the agent
	s.banAttestedNode(agentID)

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, codes.PermissionDenied, "agent is banned")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestFetchX509SVIDWithUnattestedAgent() {
	s.requireFetchX509SVIDAuthFailure(`agent "spiffe://example.org/spire/agent/test/id" is not attested`)
}

func (s *HandlerSuite) TestFetchX509SVIDLimits() {
	s.attestAgent()

	// Test with no CSRs (no count should be added)
	s.limiter.setNextError(errors.New("limit exceeded"))
	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{},
		codes.ResourceExhausted, "limit exceeded")
	s.Equal(0, s.limiter.callsFor(CSRMsg))

	// Test with 5 CSRs (5 count should be added)
	s.limiter.setNextError(errors.New("limit exceeded"))
	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{Csrs: map[string][]byte{
		"foo": {1}, "bar": {2}, "boo": {3}, "far": {4}, "bor": {5}},
	}, codes.ResourceExhausted, "limit exceeded")
	s.Equal(5, s.limiter.callsFor(CSRMsg))
}

func (s *HandlerSuite) TestFetchX509SVIDWithNoRegistrationEntries() {
	s.attestAgent()
	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{})
	s.assertBundlesInUpdate(upd)
}

func (s *HandlerSuite) TestFetchX509SVIDWithNoCSRs() {
	s.attestAgent()

	s.createBundle(otherDomainBundle)
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:      agentID,
		SpiffeId:      workloadID,
		Selectors:     irrelevantSelectors,
		FederatesWith: []string{otherDomainID},
	})
	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd, otherDomainBundle)
	s.Empty(upd.Svids)
}

func (s *HandlerSuite) TestFetchX509SVIDWithCache() {
	s.attestAgent()
	s.createBundle(otherDomainBundle)
	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:      agentID,
		SpiffeId:      workloadID,
		Selectors:     irrelevantSelectors,
		FederatesWith: []string{otherDomainID},
	})
	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)

	// agentId is not cached
	_, ok := s.fetchRegistrationEntriesCache.Get(agentID)
	s.Require().False(ok)

	_, ok = s.fetchRegistrationEntriesCache.Get(workloadID)
	s.Require().True(ok)

	s.assertBundlesInUpdate(upd, otherDomainBundle)
	s.Empty(upd.Svids)
}

func (s *HandlerSuite) TestFetchX509SVIDWithMalformedCSR() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs: map[string][]byte{"an-entry-id": []byte("MALFORMED")},
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains("Failed to sign CSRs")
}

func (s *HandlerSuite) TestFetchX509SVIDWithUnauthorizedCSR() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs("an-entry-id", workloadID),
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains(`Failed to sign CSRs`)
}

func (s *HandlerSuite) TestFetchX509SVIDWithAgentCSR() {
	// After node attestation
	s.attestAgent()
	attNode := s.fetchAttestedNode()

	// Current SVID is active
	s.NotEmpty(attNode.CertSerialNumber)
	s.NotEmpty(attNode.CertNotAfter)

	// New SVID is empty
	s.Empty(attNode.NewCertSerialNumber)
	s.Empty(attNode.NewCertNotAfter)

	// After SVID rotation
	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		// Since there is not a registration entry for the agent ID, spiffeID is used as key
		Csrs: s.makeCSRs(agentID, agentID),
	})

	s.Empty(upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	svidChain := s.assertSVIDsInUpdate(upd, map[string]string{agentID: agentID})[0]

	// Assert an attested node entry has been updated
	nodeAfterRotation := s.fetchAttestedNode()
	s.Require().NotNil(nodeAfterRotation)
	s.Equal("test", nodeAfterRotation.AttestationDataType)
	s.Equal(agentID, nodeAfterRotation.SpiffeId)

	// The initial SVID is still active
	s.Equal(attNode.CertSerialNumber, nodeAfterRotation.CertSerialNumber)
	s.Equal(attNode.CertNotAfter, nodeAfterRotation.CertNotAfter)

	// The new SVID is not empty and is the same than the one sent back to the agent
	s.Equal(svidChain[0].SerialNumber.String(), nodeAfterRotation.NewCertSerialNumber)
	s.WithinDuration(svidChain[0].NotAfter, time.Unix(nodeAfterRotation.NewCertNotAfter, 0), 0)

	// After the first request validation
	s.NoError(s.handler.validateAgentSVID(context.Background(), svidChain[0]))
	nodeAfterActivation := s.fetchAttestedNode()

	// The new SVID is activated and set as current
	s.Equal(nodeAfterActivation.CertSerialNumber, nodeAfterRotation.NewCertSerialNumber)
	s.Equal(nodeAfterActivation.CertNotAfter, nodeAfterRotation.NewCertNotAfter)

	// The 'new' slot is now empty
	s.Empty(nodeAfterActivation.NewCertSerialNumber)
	s.Empty(nodeAfterActivation.NewCertNotAfter)
}

func (s *HandlerSuite) TestFetchX509SVIDWithStaleAgent() {
	// make a copy of the agent SVID and tweak the serial number
	// before "attesting"
	agentSVID := *s.agentSVID[0]
	agentSVID.SerialNumber = big.NewInt(9999999999)
	s.Require().NoError(createAttestationEntry(context.Background(), s.ds, &agentSVID, "test"))

	s.requireFetchX509SVIDAuthFailure(`agent "spiffe://example.org/spire/agent/test/id" SVID does not match expected serial number`)
}

func (s *HandlerSuite) TestFetchX509SVIDWithDownstreamCSR() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs("an-entry-id", trustDomainID),
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains(`Failed to sign CSRs`)
}

func (s *HandlerSuite) TestFetchX509CASVIDWithUnauthorizedDownstreamCSR() {
	s.attestAgent()

	_, err := s.attestedClient.FetchX509CASVID(context.Background(), &node.FetchX509CASVIDRequest{
		Csr: s.makeCSR(trustDomainID),
	})
	s.RequireGRPCStatus(err, codes.PermissionDenied, "peer is not a valid downstream SPIRE server")
	s.assertLastLogMessageContains(`Peer is not a valid downstream SPIRE server`)
}

func (s *HandlerSuite) TestFetchX509CASVID() {
	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   trustDomainID,
		SpiffeId:   agentID,
		Selectors:  irrelevantSelectors,
		Downstream: true,
		// add a DNS name. we'll assert it does not influence the CA certificate.
		DnsNames: []string{"ca-dns1"},
	})

	resp, err := s.attestedClient.FetchX509CASVID(context.Background(), &node.FetchX509CASVIDRequest{
		Csr: s.makeCSR(trustDomainID),
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Svid)
	s.Require().NotNil(resp.Bundle)

	chain, err := x509.ParseCertificates(resp.Svid.CertChain)
	s.Require().NoError(err)
	s.Require().Len(chain, 1)
	s.Empty(chain[0].DNSNames)
	s.Equal("CN=FAKE SERVER CA,OU=DOWNSTREAM-1", chain[0].Subject.String())
}

func (s *HandlerSuite) TestFetchX509SVIDWithWorkloadCSR() {
	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  agentID,
		SpiffeId:  workloadID,
		Selectors: irrelevantSelectors,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs(entry.EntryId, workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	s.assertSVIDsInUpdate(upd, map[string]string{entry.EntryId: workloadID})
}

func (s *HandlerSuite) TestFetchX509SVIDWithSingleDNS() {
	dnsList := []string{"somehost1"}

	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  agentID,
		SpiffeId:  workloadID,
		Selectors: irrelevantSelectors,
		DnsNames:  dnsList,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs(entry.EntryId, workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	chains := s.assertSVIDsInUpdate(upd, map[string]string{entry.EntryId: workloadID})
	s.Equal(dnsList, chains[0][0].DNSNames)
	s.Equal("somehost1", chains[0][0].Subject.CommonName)
}

func (s *HandlerSuite) TestFetchX509SVIDWithMultipleDNS() {
	dnsList := []string{"somehost1", "somehost2", "somehost3"}

	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  agentID,
		SpiffeId:  workloadID,
		Selectors: irrelevantSelectors,
		DnsNames:  dnsList,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs(entry.EntryId, workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	chains := s.assertSVIDsInUpdate(upd, map[string]string{entry.EntryId: workloadID})
	s.Equal(dnsList, chains[0][0].DNSNames)
	s.Equal("somehost1", chains[0][0].Subject.CommonName)
}

func (s *HandlerSuite) TestFetchJWTSVIDWithUnattestedAgent() {
	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{},
		codes.PermissionDenied, `agent "spiffe://example.org/spire/agent/test/id" is not attested`)
}

func (s *HandlerSuite) TestFetchJWTSVIDLimits() {
	s.attestAgent()

	s.limiter.setNextError(errors.New("limit exceeded"))
	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{},
		codes.ResourceExhausted, "limit exceeded")
	// FetchJWTSVID always adds 1 count
	s.Equal(1, s.limiter.callsFor(JSRMsg))
}

func (s *HandlerSuite) TestFetchJWTSVIDWithMissingJSR() {
	s.attestAgent()

	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{},
		codes.InvalidArgument, "request missing JSR")
}

func (s *HandlerSuite) TestFetchJWTSVIDWithMissingSpiffeID() {
	s.attestAgent()

	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			Audience: []string{"audience"},
		},
	}, codes.InvalidArgument, "request missing SPIFFE ID")
}

func (s *HandlerSuite) TestFetchJWTSVIDWithMissingAudience() {
	s.attestAgent()

	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: workloadID,
		},
	}, codes.InvalidArgument, "request missing audience")
}

func (s *HandlerSuite) TestFetchJWTSVIDWithAgentID() {
	s.attestAgent()

	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: agentID,
			Audience: []string{"audience"},
		},
	}, codes.PermissionDenied, `caller is not authorized`)
}

func (s *HandlerSuite) TestFetchJWTSVIDWithUnauthorizedSPIFFEID() {
	s.attestAgent()

	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: workloadID,
			Audience: []string{"audience"},
		},
	}, codes.PermissionDenied, `caller is not authorized`)
}

func (s *HandlerSuite) TestFetchJWTSVIDWithWorkloadID() {
	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  agentID,
		SpiffeId:  workloadID,
		Selectors: irrelevantSelectors,
	})

	svid := s.requireFetchJWTSVIDSuccess(&node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: workloadID,
			Audience: []string{"audience"},
		},
	})

	s.NotEmpty(svid.Token)
	s.Equal(s.clock.Now().Unix(), svid.IssuedAt)
	s.Equal(s.clock.Now().Add(s.serverCA.JWTSVIDTTL()).Unix(), svid.ExpiresAt)
}

func (s *HandlerSuite) TestPushJWTKeyUpstreamWithoutUpstreamAuthority() {
	preExistentJwtSigningKey, _ := pemutil.ParseSigner([]byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgchJzydaeUKOV6IjL
B/8CXIhS797GajySZWNNFRqM/jChRANCAATcHYgISDwxmf0fulS8NRaMqItrplrk
UigDxnLeJxW17hsOD8xO8J7WdHMaIhXvrTx7EhxWC1hpCXCsxn6UVlLL
-----END PRIVATE KEY-----`))
	pkixBytes, err := x509.MarshalPKIXPublicKey(preExistentJwtSigningKey.Public())
	s.Require().NoError(err)
	// Append one JWK on the bundle, so it must be reported in the result of PushJWTKeyUpstream
	// along with the JWK sent on the request.
	_, err = s.ds.AppendBundle(context.Background(),
		&datastore.AppendBundleRequest{
			Bundle: &common.Bundle{
				TrustDomainId: trustDomainID,
				JwtSigningKeys: []*common.PublicKey{
					{
						Kid:       "kid1",
						PkixBytes: pkixBytes,
					},
				},
			},
		})
	s.Require().NoError(err)

	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   trustDomainID,
		SpiffeId:   agentID,
		Selectors:  irrelevantSelectors,
		Downstream: true,
	})

	s.Require().Len(s.fetchBundle().JwtSigningKeys, 1)

	pkixBytes, err = x509.MarshalPKIXPublicKey(jwtSigningKey.Public())
	s.Require().NoError(err)

	resp, err := s.attestedClient.PushJWTKeyUpstream(context.Background(), &node.PushJWTKeyUpstreamRequest{
		JwtKey: &common.PublicKey{
			Kid:       "kid2",
			PkixBytes: pkixBytes,
		},
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Len(resp.JwtSigningKeys, 2)
	s.Require().Equal("kid1", resp.JwtSigningKeys[0].Kid)
	s.Require().Equal("kid2", resp.JwtSigningKeys[1].Kid)
	s.Require().Len(s.fetchBundle().JwtSigningKeys, 2)
}

func (s *HandlerSuite) TestPushJWTKeyUpstreamWithUpstreamAuthority() {
	s.setupTest(&fakeupstreamauthority.Config{
		TrustDomain: trustDomainID,
	})

	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtSigningKey.Public())
	s.Require().NoError(err)
	jwk := &common.PublicKey{
		Kid:       "kid",
		PkixBytes: pkixBytes,
	}

	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   trustDomainID,
		SpiffeId:   agentID,
		Selectors:  irrelevantSelectors,
		Downstream: true,
	})

	s.Require().Len(s.fetchBundle().JwtSigningKeys, 0)

	resp, err := s.attestedClient.PushJWTKeyUpstream(context.Background(), &node.PushJWTKeyUpstreamRequest{
		JwtKey: jwk,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Len(resp.JwtSigningKeys, 1)
	s.Require().Equal("kid", resp.JwtSigningKeys[0].Kid)
	s.Len(s.fetchBundle().JwtSigningKeys, 1)
}

func (s *HandlerSuite) TestPushJWTKeyUpstreamUnimplemented() {
	s.setupTest(&fakeupstreamauthority.Config{
		TrustDomain:           trustDomainID,
		DisallowPublishJWTKey: true,
	})

	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   trustDomainID,
		SpiffeId:   agentID,
		Selectors:  irrelevantSelectors,
		Downstream: true,
	})

	s.Require().Len(s.fetchBundle().JwtSigningKeys, 0)

	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtSigningKey.Public())
	s.Require().NoError(err)

	resp, err := s.attestedClient.PushJWTKeyUpstream(context.Background(), &node.PushJWTKeyUpstreamRequest{
		JwtKey: &common.PublicKey{
			Kid:       "kid",
			PkixBytes: pkixBytes,
		},
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Len(resp.JwtSigningKeys, 1)
	s.Require().Equal("kid", resp.JwtSigningKeys[0].Kid)
	s.Len(s.fetchBundle().JwtSigningKeys, 1)
	s.assertLastLogLevelAndMessage(logrus.WarnLevel, "UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed "+
		"by this server may have trouble communicating with workloads outside "+
		"this cluster when using JWT-SVIDs.")
}

func (s *HandlerSuite) TestAuthorizeCallUnhandledMethod() {
	ctx, err := s.handler.AuthorizeCall(context.Background(), "/spire.api.node.Node/Foo")
	s.Require().Error(err)
	s.Equal(codes.PermissionDenied, status.Code(err))
	s.Equal(`authorization not implemented for method "/spire.api.node.Node/Foo"`, status.Convert(err).Message())
	s.Require().Nil(ctx)
}

func (s *HandlerSuite) TestAuthorizeCallForAlwaysAuthorizedCalls() {
	// Attest() is always authorized (context is not embellished)
	ctx, err := s.handler.AuthorizeCall(context.Background(), "/spire.api.node.Node/Attest")
	s.Require().NoError(err)
	s.Require().Equal(context.Background(), ctx)
}

func (s *HandlerSuite) TestAuthorizeCallForFetchX509SVID() {
	s.testAuthorizeCallRequiringAgentSVID("FetchX509SVID")
}

func (s *HandlerSuite) TestAuthorizeCallForFetchJWTSVID() {
	s.testAuthorizeCallRequiringAgentSVID("FetchJWTSVID")
}

func (s *HandlerSuite) TestAuthorizeCallForFetchX509CASVID() {
	peerCert := s.downstreamSVID[0]
	peerCtx := withPeerCert(context.Background(), s.downstreamSVID)

	const fullMethod = "/spire.api.node.Node/FetchX509CASVID"

	// no downstream registration entry
	ctx, err := s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, "peer is not a valid downstream SPIRE server")
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`Peer is not a valid downstream SPIRE server`)

	// with downstream registration entry
	downstreamEntry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   agentID,
		SpiffeId:   downstreamID,
		Selectors:  irrelevantSelectors,
		Downstream: true,
	})
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.Require().NoError(err)
	actualEntry, ok := getDownstreamEntry(ctx)
	s.Require().True(ok, "context has downstream entry")
	s.RequireProtoEqual(downstreamEntry, actualEntry)

	s.testAuthorizeCallRequiringClientCert(peerCtx, fullMethod, "downstream SVID is required for this request",
		"Downstream SVID is required for this request", peerCert)
}

func (s *HandlerSuite) testAuthorizeCallRequiringAgentSVID(method string) {
	peerCert := s.agentSVID[0]
	peerCtx := withPeerCert(context.Background(), s.agentSVID)

	fullMethod := fmt.Sprintf("/spire.api.node.Node/%s", method)

	// no attested certificate with matching SPIFFE ID
	ctx, err := s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, `agent "spiffe://example.org/spire/agent/test/id" is not attested`)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`Agent permission denied`)
	s.assertPermissionDeniedDetails(err, types.PermissionDeniedDetails_AGENT_NOT_ATTESTED)

	s.attestAgent()
	s.testAuthorizeCallRequiringClientCert(peerCtx, fullMethod, "agent SVID is required for this request",
		"Agent SVID is required for this request", peerCert)

	// expired certificate
	s.clock.Set(peerCert.NotAfter.Add(time.Second))
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, `agent "spiffe://example.org/spire/agent/test/id" SVID has expired`)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`Agent permission denied`)
	s.clock.Set(peerCert.NotAfter)
	s.assertPermissionDeniedDetails(err, types.PermissionDeniedDetails_AGENT_EXPIRED)

	// serial number does not match
	s.updateAttestedNode(agentID, "SERIAL NUMBER", peerCert.NotAfter)
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, `agent "spiffe://example.org/spire/agent/test/id" SVID does not match expected serial number`)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`Agent permission denied`)
	s.assertPermissionDeniedDetails(err, types.PermissionDeniedDetails_AGENT_NOT_ACTIVE)

	// banned agent
	s.banAttestedNode(agentID)
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, `agent "spiffe://example.org/spire/agent/test/id" is banned`)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`Agent permission denied`)
	s.assertPermissionDeniedDetails(err, types.PermissionDeniedDetails_AGENT_BANNED)
}

func (s *HandlerSuite) TestFetchBundle() {
	resp, err := s.attestedClient.FetchBundle(context.Background(), &node.FetchBundleRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().True(proto.Equal(s.fetchBundle(), resp.Bundle))
}

func (s *HandlerSuite) TestAuthorizeCallForFetchBundle() {
	peerCtx := withPeerCert(context.Background(), s.workloadSVID)
	peerCert := s.workloadSVID[0]
	s.testAuthorizeCallRequiringClientCert(peerCtx, "/spire.api.node.Node/FetchBundle",
		"client certificate required for this request",
		"Client certificate required for this request", peerCert)
}

func (s *HandlerSuite) testAuthorizeCallRequiringClientCert(peerCtx context.Context, method, gprcStatusMsg, logMsg string, peerCert *x509.Certificate) {
	// no peer context
	ctx, err := s.handler.AuthorizeCall(context.Background(), method)
	s.RequireGRPCStatus(err, codes.Unauthenticated, gprcStatusMsg)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(logMsg)

	// non-TLS peer context
	ctx, err = s.handler.AuthorizeCall(peer.NewContext(context.Background(), &peer.Peer{}), method)
	s.RequireGRPCStatus(err, codes.Unauthenticated, gprcStatusMsg)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(logMsg)

	// no verified chains on TLS peer context
	ctx, err = s.handler.AuthorizeCall(peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{},
	}), method)
	s.RequireGRPCStatus(err, codes.Unauthenticated, gprcStatusMsg)
	s.Require().Nil(ctx)
	s.assertLastLogMessage(logMsg)

	// good certificate
	ctx, err = s.handler.AuthorizeCall(peerCtx, method)
	s.Require().NoError(err)
	actualCert, ok := getPeerCertificate(ctx)
	s.Require().True(ok, "context has peer certificate")
	s.Require().True(peerCert.Equal(actualCert), "peer certificate matches")
}

func (s *HandlerSuite) addAttestor(config fakeservernodeattestor.Config) {
	var p nodeattestor.NodeAttestor
	s.LoadPlugin(catalog.MakePlugin("test", nodeattestor.PluginServer(fakeservernodeattestor.New("test", config))), &p)
	s.catalog.AddNodeAttestorNamed("test", p)
}

func (s *HandlerSuite) addResolver(name string, config fakenoderesolver.Config) {
	var p noderesolver.NodeResolver
	s.LoadPlugin(catalog.MakePlugin(name, noderesolver.PluginServer(fakenoderesolver.New(name, config))), &p)
	s.catalog.AddNodeResolverNamed(name, p)
}

func (s *HandlerSuite) createBundle(bundle *common.Bundle) {
	_, err := s.ds.CreateBundle(context.Background(), &datastore.CreateBundleRequest{
		Bundle: bundle,
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) createJoinToken(token string, expiresAt time.Time) {
	_, err := s.ds.CreateJoinToken(context.Background(), &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  token,
			Expiry: expiresAt.Unix(),
		},
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) fetchJoinToken(token string) *datastore.JoinToken {
	resp, err := s.ds.FetchJoinToken(context.Background(), &datastore.FetchJoinTokenRequest{
		Token: token,
	})
	s.Require().NoError(err)
	return resp.JoinToken
}

func (s *HandlerSuite) attestAgent() {
	s.Require().NoError(createAttestationEntry(context.Background(), s.ds, s.agentSVID[0], "test"))
}

func (s *HandlerSuite) createAttestedNode(n *common.AttestedNode) {
	_, err := s.ds.CreateAttestedNode(context.Background(), &datastore.CreateAttestedNodeRequest{
		Node: n,
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) updateAttestedNode(spiffeID, serialNumber string, notAfter time.Time) {
	_, err := s.ds.UpdateAttestedNode(context.Background(), &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         spiffeID,
		CertSerialNumber: serialNumber,
		CertNotAfter:     notAfter.Unix(),
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) banAttestedNode(spiffeID string) {
	_, err := s.ds.UpdateAttestedNode(context.Background(), &datastore.UpdateAttestedNodeRequest{
		SpiffeId: spiffeID,
		InputMask: &common.AttestedNodeMask{
			CertSerialNumber:    true,
			NewCertSerialNumber: true,
		},
	})
	s.Require().NoError(err)
}

func (s *HandlerSuite) fetchAttestedNode() *common.AttestedNode {
	resp, err := s.ds.FetchAttestedNode(context.Background(), &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	return resp.Node
}

func (s *HandlerSuite) getNodeSelectors() []*common.Selector {
	resp, err := s.ds.GetNodeSelectors(context.Background(), &datastore.GetNodeSelectorsRequest{
		SpiffeId: agentID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Selectors)
	s.Require().Equal(agentID, resp.Selectors.SpiffeId)
	return resp.Selectors.Selectors
}

func (s *HandlerSuite) createRegistrationEntry(entry *common.RegistrationEntry) *common.RegistrationEntry {
	resp, err := s.ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
		Entry: entry,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp.Entry)
	return resp.Entry
}

func (s *HandlerSuite) requireAttestSuccess(req *node.AttestRequest, expectedSPIFFE string, responses ...string) *node.X509SVIDUpdate {
	expectedCounter := telemetry_server.StartNodeAPIAttestCall(s.expectedMetrics)
	defer expectedCounter.Done(nil)
	telemetry_common.AddAttestorType(expectedCounter, req.AttestationData.Type)

	authorizeCounter := telemetry_server.StartNodeAPIAuthorizeCall(s.expectedMetrics, "_spire_api_node_Node_Attest")
	defer authorizeCounter.Done(nil)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.unattestedClient.Attest(ctx)
	s.Require().NoError(err)
	s.Require().NoError(stream.Send(req))
	for _, response := range responses {
		resp, err := stream.Recv()
		s.Require().NoError(err)
		s.Require().NotNil(resp)
		s.Require().NotEmpty(resp.Challenge, "expected a challenge")
		s.Require().Nil(resp.SvidUpdate, "expected a challenge, which shouldn't contain an update")

		s.Require().NoError(stream.Send(&node.AttestRequest{
			Response: []byte(response),
		}))
	}
	s.Require().NoError(stream.CloseSend())
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.SvidUpdate)

	s.NotNil(resp.SvidUpdate.Svids[expectedSPIFFE])

	// ensure end of stream so server-side telemetry is done
	eofResp, err := stream.Recv()
	s.Require().Nil(eofResp)
	s.Require().Equal(io.EOF, err)

	return resp.SvidUpdate
}

func (s *HandlerSuite) requireAttestFailure(req *node.AttestRequest, errorCode codes.Code, errorContains string) {
	expectedCounter := telemetry_server.StartNodeAPIAttestCall(s.expectedMetrics)
	if req.AttestationData != nil && req.AttestationData.Type != "" {
		telemetry_common.AddAttestorType(expectedCounter, req.AttestationData.Type)
	} else {
		telemetry_common.AddAttestorType(expectedCounter, "")
	}
	expectErr := status.Error(errorCode, "")
	defer expectedCounter.Done(&expectErr)

	authorizeCounter := telemetry_server.StartNodeAPIAuthorizeCall(s.expectedMetrics, "_spire_api_node_Node_Attest")
	defer authorizeCounter.Done(nil)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.unattestedClient.Attest(ctx)
	s.Require().NoError(err)
	s.Require().NoError(stream.Send(req))
	s.Require().NoError(stream.CloseSend())
	resp, err := stream.Recv()
	s.requireErrorContains(err, errorContains)
	s.Require().Equal(errorCode, status.Code(err))
	s.Require().Nil(resp)
}

func (s *HandlerSuite) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := &tls.Certificate{
		PrivateKey: testKey,
	}
	for _, cert := range s.agentSVID {
		c.Certificate = append(c.Certificate, cert.Raw)
	}
	return c, nil
}

func (s *HandlerSuite) requireFetchX509SVIDSuccess(req *node.FetchX509SVIDRequest) *node.X509SVIDUpdate {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.attestedClient.FetchX509SVID(ctx)
	s.Require().NoError(err)
	s.Require().NoError(stream.Send(req))
	s.Require().NoError(stream.CloseSend())
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.SvidUpdate)
	return resp.SvidUpdate
}

func (s *HandlerSuite) requireFetchX509SVIDFailure(req *node.FetchX509SVIDRequest, errorCode codes.Code, errorContains string) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.attestedClient.FetchX509SVID(ctx)
	s.Require().NoError(err)
	s.Require().NoError(stream.Send(req))
	s.Require().NoError(stream.CloseSend())
	resp, err := stream.Recv()
	s.Require().Contains(errorContains, status.Convert(err).Message())
	s.Require().Equal(errorCode, status.Code(err))
	s.Require().Nil(resp)
}

func (s *HandlerSuite) requireFetchX509SVIDAuthFailure(expectedErr string) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.attestedClient.FetchX509SVID(ctx)
	s.Require().NoError(err)
	// the auth failure will come back on the Recv(). we shouldn't have to send
	// on the stream to get this to happen.
	resp, err := stream.Recv()
	s.RequireGRPCStatus(err, codes.PermissionDenied, expectedErr)
	s.Require().Nil(resp)
}

func (s *HandlerSuite) requireFetchJWTSVIDSuccess(req *node.FetchJWTSVIDRequest) *node.JWTSVID {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	resp, err := s.attestedClient.FetchJWTSVID(ctx, req)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Svid)
	return resp.Svid
}

func (s *HandlerSuite) requireFetchJWTSVIDFailure(req *node.FetchJWTSVIDRequest, errorCode codes.Code, errorContains string) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	resp, err := s.attestedClient.FetchJWTSVID(ctx, req)
	s.Require().Contains(status.Convert(err).Message(), errorContains)
	s.Require().Equal(errorCode, status.Code(err))
	s.Require().Nil(resp)
}

func (s *HandlerSuite) assertBundlesInUpdate(upd *node.X509SVIDUpdate, federatedBundles ...*common.Bundle) {
	// Bundles should have an entry for the trust domain and each federated domain
	s.Len(upd.Bundles, 1+len(federatedBundles))
	s.True(proto.Equal(upd.Bundles[trustDomainID], s.bundle))
	for _, federatedBundle := range federatedBundles {
		s.True(proto.Equal(
			upd.Bundles[federatedBundle.TrustDomainId],
			federatedBundle,
		))
	}
}

func (s *HandlerSuite) assertSVIDsInUpdate(upd *node.X509SVIDUpdate, spiffeIDs map[string]string) [][]*x509.Certificate {
	s.Len(upd.Svids, len(spiffeIDs), "number of SVIDs in update")

	var svidChains [][]*x509.Certificate
	for entryID := range spiffeIDs {
		svidEntry := upd.Svids[entryID]
		if !s.NotNil(svidEntry, "svid entry") {
			continue
		}

		// Assert SVID chain is well formed
		svidChain, err := x509.ParseCertificates(svidEntry.CertChain)
		if !s.NoError(err, "parsing svid cert chain") {
			continue
		}

		s.Len(svidChain, 1)

		// ExpiresAt should match NotAfter in first certificate in SVID chain
		s.WithinDuration(svidChain[0].NotAfter, time.Unix(svidEntry.ExpiresAt, 0), 0)

		svidChains = append(svidChains, svidChain)
	}

	s.Require().Len(svidChains, len(spiffeIDs), "# of good svids in update")
	return svidChains
}

func (s *HandlerSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}

func (s *HandlerSuite) assertLastLogLevelAndMessage(level logrus.Level, message string) {
	entry := s.logHook.LastEntry()
	if s.NotNil(entry) {
		s.Equal(message, entry.Message)
		s.Equal(level, entry.Level)
	}
}

func (s *HandlerSuite) assertLastLogMessage(message string) {
	entry := s.logHook.LastEntry()
	if s.NotNil(entry) {
		s.Equal(message, entry.Message)
	}
}

func (s *HandlerSuite) assertPermissionDeniedDetails(err error, reason types.PermissionDeniedDetails_Reason) {
	st := status.Convert(err)
	if s.Equal(codes.PermissionDenied, st.Code()) {
		s.Equal([]interface{}{
			&types.PermissionDeniedDetails{
				Reason: reason,
			},
		}, st.Details())
	}
}

func (s *HandlerSuite) assertLastLogMessageContains(contains string) {
	entry := s.logHook.LastEntry()
	if s.NotNil(entry) {
		s.Contains(entry.Message, contains)
	}
}

func (s *HandlerSuite) makeSVID(spiffeID string) []*x509.Certificate {
	svid, err := s.serverCA.SignX509SVID(context.Background(), ca.X509SVIDParams{
		SpiffeID:  spiffeID,
		PublicKey: testKey.Public(),
	})
	s.Require().NoError(err)
	return svid
}

func (s *HandlerSuite) makeCSR(spiffeID string) []byte {
	csr, err := util.MakeCSR(testKey, spiffeID)
	s.Require().NoError(err)
	return csr
}

func (s *HandlerSuite) makeCSRWithoutURISAN() []byte {
	csr, err := util.MakeCSRWithoutURISAN(testKey)
	s.Require().NoError(err)
	return csr
}

func (s *HandlerSuite) makeCSRs(entryID, spiffeID string) map[string][]byte {
	csrs := make(map[string][]byte)
	csrs[entryID] = s.makeCSR(spiffeID)
	return csrs
}

func (s *HandlerSuite) fetchBundle() *common.Bundle {
	r, err := s.ds.FetchBundle(context.Background(), &datastore.FetchBundleRequest{
		TrustDomainId: trustDomainID,
	})
	s.Require().NoError(err)
	return r.Bundle
}

type fakeLimiter struct {
	callsForAttest int
	callsForCSR    int
	callsForJSR    int

	nextError error

	mtx sync.Mutex
}

func (fl *fakeLimiter) Limit(_ context.Context, msgType, count int) error {
	fl.mtx.Lock()
	defer fl.mtx.Unlock()

	switch msgType {
	case AttestMsg:
		fl.callsForAttest += count
	case CSRMsg:
		fl.callsForCSR += count
	case JSRMsg:
		fl.callsForJSR += count
	}

	if fl.nextError != nil {
		err := fl.nextError
		fl.nextError = nil
		return err
	}

	return nil
}

func (fl *fakeLimiter) setNextError(err error) {
	fl.mtx.Lock()
	defer fl.mtx.Unlock()
	fl.nextError = err
}

func (fl *fakeLimiter) callsFor(msgType int) int {
	fl.mtx.Lock()
	defer fl.mtx.Unlock()

	switch msgType {
	case AttestMsg:
		return fl.callsForAttest
	case CSRMsg:
		return fl.callsForCSR
	case JSRMsg:
		return fl.callsForJSR
	}

	return 0
}

func makeAttestationData(typ, data string) *common.AttestationData {
	return &common.AttestationData{Type: typ, Data: []byte(data)}
}

func withPeerCert(ctx context.Context, certChain []*x509.Certificate) context.Context {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	return peer.NewContext(ctx, &peer.Peer{
		Addr: addr,
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{certChain},
			},
		},
	})
}
