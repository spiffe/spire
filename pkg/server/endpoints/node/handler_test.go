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
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/auth"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_common "github.com/spiffe/spire/pkg/common/telemetry/common"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/spiffe/spire/proto/spire/server/noderesolver"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakenoderesolver"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeservernodeattestor"
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
	joinTokenID  = "spiffe://example.org/spire/agent/join_token/TOKEN"
	// make more clear in code when no ID is passed as expected param
	noIDExpected = ""

	// used to cancel stream operations on test failure instead of blocking the
	// full go test timeout period (i.e. 10 minutes)
	testTimeout = time.Minute
)

var (
	trustDomainURL, _ = idutil.ParseSpiffeID(trustDomainID, idutil.AllowAnyTrustDomain())

	otherDomainBundle = &common.Bundle{
		TrustDomainId: otherDomainID,
	}

	testKey, _ = pemutil.ParseECPrivateKey([]byte(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUdF3LNDNZWKYQHFj
UIs5TNt4LXDawuZFFj2J7D1T9mehRANCAASEhjkDbIFdNaZ9EneJaSXKfLiBDqt2
l37cUGNqRvIYDhSH/IJycqxLTtvHoYMHLSV9N5UHIFgPJ/30RCBQiH3t
-----END PRIVATE KEY-----
`))
)

func TestHandler(t *testing.T) {
	spiretest.Run(t, new(HandlerSuite))
}

type HandlerSuite struct {
	spiretest.Suite

	server           *grpc.Server
	logHook          *test.Hook
	limiter          *fakeLimiter
	handler          *Handler
	metrics          *fakemetrics.FakeMetrics
	expectedMetrics  *fakemetrics.FakeMetrics
	unattestedClient node.NodeClient
	attestedClient   node.NodeClient
	ds               *fakedatastore.DataStore
	catalog          *fakeservercatalog.Catalog
	clock            *clock.Mock
	bundle           *common.Bundle
	agentSVID        []*x509.Certificate
	downstreamSVID   []*x509.Certificate
	serverCA         *fakeserverca.CA
}

func (s *HandlerSuite) SetupTest() {
	s.clock = clock.NewMock(s.T())

	log, logHook := test.NewNullLogger()
	s.logHook = logHook

	s.limiter = new(fakeLimiter)

	s.ds = fakedatastore.New()
	s.catalog = fakeservercatalog.New()
	s.catalog.SetDataStore(s.ds)

	s.serverCA = fakeserverca.New(s.T(), trustDomain, &fakeserverca.Options{
		Clock: s.clock,
	})
	s.bundle = bundleutil.BundleProtoFromRootCAs(trustDomainID, s.serverCA.Bundle())

	s.createBundle(s.bundle)

	// Create server and agent SVIDs for TLS communication
	serverSVID := s.makeSVID(serverID)
	s.agentSVID = s.makeSVID(agentID)
	s.downstreamSVID = s.makeSVID(downstreamID)

	s.metrics = fakemetrics.New()
	s.expectedMetrics = fakemetrics.New()

	handler := NewHandler(HandlerConfig{
		Log:         log,
		Metrics:     s.metrics,
		Catalog:     s.catalog,
		ServerCA:    s.serverCA,
		TrustDomain: *trustDomainURL,
		Clock:       s.clock,
	})
	handler.limiter = s.limiter

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
	go server.Serve(listener)

	unattestedConn, err := grpc.Dial(listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			// skip verification of the server certificate. otherwise we'd
			// need SANs to allow the connection over localhost. this isn't
			// important for these tests.
			InsecureSkipVerify: true,
		})))
	s.Require().NoError(err)

	attestedConn, err := grpc.Dial(listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			// skip verification of the server certificate. otherwise we'd
			// need SANs to allow the connection over localhost. this isn't
			// important for these tests.
			InsecureSkipVerify:   true,
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
		noIDExpected, codes.ResourceExhausted, "limit exceeded")
	// Attest always adds 1 count
	s.Equal(1, s.limiter.callsFor(AttestMsg))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNoAttestationData() {
	s.requireAttestFailure(&node.AttestRequest{},
		noIDExpected, codes.InvalidArgument, "request missing attestation data")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNoAttestationDataType() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: &common.AttestationData{},
	}, noIDExpected, codes.InvalidArgument, "request missing attestation data type")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNoCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
	}, noIDExpected, codes.InvalidArgument, "request missing CSR")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithMalformedCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             []byte("MALFORMED"),
	}, noIDExpected, codes.InvalidArgument, "request CSR is invalid: failed to parse CSR")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithAgentIDFromWrongTrustDomainInCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR("spiffe://otherdomain.test/spire/agent/test/id"),
	}, noIDExpected, codes.InvalidArgument, `request CSR is invalid: invalid SPIFFE ID: "spiffe://otherdomain.test/spire/agent/test/id" does not belong to trust domain`)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithNonAgentIDInCSR() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR("spiffe://example.org"),
	}, noIDExpected, codes.InvalidArgument, `request CSR is invalid: invalid SPIFFE ID: "spiffe://example.org" is not a valid agent SPIFFE ID`)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWhenAgentAlreadyAttestedWithDeprecatedCSR() {
	s.addAttestor("test", fakeservernodeattestor.Config{
		DisallowReattestation: true,
	})

	s.createAttestedNode(&common.AttestedNode{
		SpiffeId: agentID,
	})

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR(agentID),
	}, noIDExpected, codes.Unknown, "reattestation is not permitted")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithUnknownAttestor() {
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", ""),
		Csr:             s.makeCSR(agentID),
	}, noIDExpected, codes.Unimplemented, `could not find node attestor type "test"`)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithMismatchedAgentIDWithDeprecatedCSR() {
	s.addAttestor("test", fakeservernodeattestor.Config{
		Data: map[string]string{"data": "id"},
	})

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR("spiffe://example.org/spire/agent/test/other"),
	}, agentID, codes.NotFound, "attestor returned unexpected response")

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
		FederatesWith: []string{otherDomainID},
	})

	s.addAttestor("test", fakeservernodeattestor.Config{
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
	attestedNode := s.fetchAttestedNode(agentID)
	s.Require().NotNil(attestedNode)
	s.Equal("test", attestedNode.AttestationDataType)
	s.Equal(agentID, attestedNode.SpiffeId)
	s.Equal(svidChain[0].SerialNumber.String(), attestedNode.CertSerialNumber)
	s.WithinDuration(svidChain[0].NotAfter, time.Unix(attestedNode.CertNotAfter, 0), 0)

	// No selectors were returned and no resolvers were available, so the node
	// selectors should be empty.
	s.Empty(s.getNodeSelectors(agentID))
}

func (s *HandlerSuite) TestAttestAgentless() {
	attestor := fakeservernodeattestor.Config{
		Data:          map[string]string{"data": workloadID},
		ReturnLiteral: true,
	}

	agentlessCSR := s.makeCSR(workloadID)

	// By default "/spire/agent/* is expected for attestation calls
	s.addAttestor("test", attestor)
	s.False(s.handler.c.AllowAgentlessNodeAttestors)
	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             agentlessCSR,
	}, noIDExpected, codes.InvalidArgument, "expecting \"/spire/agent/*\"")

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
	s.addAttestor("test", fakeservernodeattestor.Config{
		//CanReattest: true,
		Data: map[string]string{"data": "id"},
	})

	// Create an attested node entry
	s.createAttestedNode(&common.AttestedNode{
		SpiffeId: agentID,
	})

	// Reattest
	s.requireAttestSuccess(&node.AttestRequest{
		AttestationData: makeAttestationData("test", "data"),
		Csr:             s.makeCSR(agentID),
	}, agentID)

	// Assert the attested node entry has been updated
	attestedNode := s.fetchAttestedNode(agentID)
	s.Require().NotNil(attestedNode)
	s.Equal(agentID, attestedNode.SpiffeId)
	s.NotEmpty(attestedNode.CertSerialNumber)
	s.NotEqual(0, attestedNode.CertNotAfter)

	// Attestation data type is NOT updatable
	s.Equal("", attestedNode.AttestationDataType)

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestChallengeResponseSuccess() {
	// Make sure reattestation is allowed by the attestor
	s.addAttestor("test", fakeservernodeattestor.Config{
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
	}, noIDExpected, codes.Unknown, "failed to attest: no such token")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithAlreadyUsedJoinToken() {
	s.createAttestedNode(&common.AttestedNode{
		SpiffeId: joinTokenID,
	})

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: &common.AttestationData{Type: "join_token", Data: []byte("TOKEN")},
		Csr:             s.makeCSR(joinTokenID),
	}, noIDExpected, codes.Unknown, "failed to attest: join token has already been used")

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithExpiredJoinToken() {
	s.createJoinToken("TOKEN", s.clock.Now().Add(-time.Second))

	s.requireAttestFailure(&node.AttestRequest{
		AttestationData: makeAttestationData("join_token", "TOKEN"),
		Csr:             s.makeCSR(joinTokenID),
	}, noIDExpected, codes.Unknown, "failed to attest: join token expired")

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
	s.addAttestor("test", fakeservernodeattestor.Config{
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
	}, s.getNodeSelectors(agentID))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithOnlyResolverSelectors() {
	// configure the attestor to return selectors
	s.addAttestor("test", fakeservernodeattestor.Config{
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
	}, s.getNodeSelectors(agentID))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestAttestWithBothAttestorAndResolverSelectors() {
	// configure the attestor to return selectors
	s.addAttestor("test", fakeservernodeattestor.Config{
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

	s.Equal([]*common.Selector{
		{Type: "test", Value: "test-resolver-value"},
		{Type: "test", Value: "test-attestor-value"},
	}, s.getNodeSelectors(agentID))

	s.Equal(s.expectedMetrics.AllMetrics(), s.metrics.AllMetrics())
}

func (s *HandlerSuite) TestFetchX509SVIDWithUnattestedAgent() {
	s.requireFetchX509SVIDAuthFailure()
}

func (s *HandlerSuite) TestFetchX509SVIDWithCurrentAndLegacyCSRs() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs:           map[string][]byte{"an-entry-id": []byte("MALFORMED")},
		DEPRECATEDCsrs: [][]byte{{1, 2, 3}},
	}, codes.InvalidArgument, "cannot use 'Csrs' and 'DeprecatedCsrs' on the same 'FetchX509Request'")
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

func (s *HandlerSuite) TestFetchX509SVIDLimitsLegacy() {
	s.attestAgent()

	// Test with no CSRs (no count should be added)
	s.limiter.setNextError(errors.New("limit exceeded"))
	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{},
		codes.ResourceExhausted, "limit exceeded")
	s.Equal(0, s.limiter.callsFor(CSRMsg))

	// Test with 5 deprecated CSRs(5 count should be added)
	s.limiter.setNextError(errors.New("limit exceeded"))
	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{DEPRECATEDCsrs: make([][]byte, 5)},
		codes.ResourceExhausted, "limit exceeded")
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
		FederatesWith: []string{otherDomainID},
	})
	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd, otherDomainBundle)
	s.Empty(upd.Svids)
}

func (s *HandlerSuite) TestFetchX509SVIDWithMalformedCSR() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs: map[string][]byte{"an-entry-id": []byte("MALFORMED")},
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains("failed to parse CSR")
}

func (s *HandlerSuite) TestFetchX509SVIDWithMalformedCSRLegacy() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: [][]byte{[]byte("MALFORMED")},
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains("failed to parse CSR")
}

func (s *HandlerSuite) TestFetchX509SVIDWithUnauthorizedCSR() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs("an-entry-id", workloadID),
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains(`not entitled to sign CSR for given ID type`)
}

func (s *HandlerSuite) TestFetchX509SVIDWithUnauthorizedCSRLegacy() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: s.makeCSRsLegacy(workloadID),
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains(`not entitled to sign CSR for given ID type`)
}

func (s *HandlerSuite) TestFetchX509SVIDWithAgentCSR() {
	s.attestAgent()

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		// Since there is not a registration entry for the agent ID, spiffeID is used as key
		Csrs: s.makeCSRs(agentID, agentID),
	})

	s.Empty(upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	svidChain := s.assertSVIDsInUpdate(upd, map[string]string{agentID: agentID})[0]

	// Assert an attested node entry has been updated
	attestedNode := s.fetchAttestedNode(agentID)
	s.Require().NotNil(attestedNode)
	s.Equal("test", attestedNode.AttestationDataType)
	s.Equal(agentID, attestedNode.SpiffeId)
	s.Equal(svidChain[0].SerialNumber.String(), attestedNode.CertSerialNumber)
	s.WithinDuration(svidChain[0].NotAfter, time.Unix(attestedNode.CertNotAfter, 0), 0)
}

func (s *HandlerSuite) TestFetchX509SVIDWithAgentCSRLegacy() {
	s.attestAgent()

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: s.makeCSRsLegacy(agentID),
	})

	s.Empty(upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	svidChain := s.assertSVIDsInUpdateLegacy(upd, agentID)[0]

	// Assert an attested node entry has been updated
	attestedNode := s.fetchAttestedNode(agentID)
	s.Require().NotNil(attestedNode)
	s.Equal("test", attestedNode.AttestationDataType)
	s.Equal(agentID, attestedNode.SpiffeId)
	s.Equal(svidChain[0].SerialNumber.String(), attestedNode.CertSerialNumber)
	s.WithinDuration(svidChain[0].NotAfter, time.Unix(attestedNode.CertNotAfter, 0), 0)
}

func (s *HandlerSuite) TestFetchX509SVIDWithStaleAgent() {
	// make a copy of the agent SVID and tweak the serial number
	// before "attesting"
	agentSVID := *s.agentSVID[0]
	agentSVID.SerialNumber = big.NewInt(9999999999)
	s.Require().NoError(createAttestationEntry(context.Background(), s.ds, &agentSVID, "test"))

	s.requireFetchX509SVIDAuthFailure()
}

func (s *HandlerSuite) TestFetchX509SVIDWithDownstreamCSR() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs("an-entry-id", trustDomainID),
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains(`not entitled to sign CSR for given ID type`)
}

func (s *HandlerSuite) TestFetchX509SVIDWithDownstreamCSRLegacy() {
	s.attestAgent()

	s.requireFetchX509SVIDFailure(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: s.makeCSRsLegacy(trustDomainID),
	}, codes.Internal, "failed to sign CSRs")
	s.assertLastLogMessageContains(`not entitled to sign CSR for given ID type`)
}

func (s *HandlerSuite) TestFetchX509CASVIDWithUnauthorizedDownstreamCSR() {
	s.attestAgent()

	_, err := s.attestedClient.FetchX509CASVID(context.Background(), &node.FetchX509CASVIDRequest{
		Csr: s.makeCSR(trustDomainID),
	})
	s.RequireGRPCStatus(err, codes.PermissionDenied, "peer is not a valid downstream SPIRE server")
	s.assertLastLogMessageContains(`"spiffe://example.org/spire/agent/test/id" is not an authorized downstream workload`)
}

func (s *HandlerSuite) TestFetchX509CASVID() {
	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   trustDomainID,
		SpiffeId:   agentID,
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
		ParentId: agentID,
		SpiffeId: workloadID,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		Csrs: s.makeCSRs(entry.EntryId, workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	s.assertSVIDsInUpdate(upd, map[string]string{entry.EntryId: workloadID})
}

func (s *HandlerSuite) TestFetchX509SVIDWithWorkloadCSRLegacy() {
	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: workloadID,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: s.makeCSRsLegacy(workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	s.assertSVIDsInUpdateLegacy(upd, workloadID)
}

func (s *HandlerSuite) TestFetchX509SVIDWithSingleDNS() {
	dnsList := []string{"somehost1"}

	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: workloadID,
		DnsNames: dnsList,
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

func (s *HandlerSuite) TestFetchX509SVIDWithSingleDNSLegacy() {
	dnsList := []string{"somehost1"}

	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: workloadID,
		DnsNames: dnsList,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: s.makeCSRsLegacy(workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	chains := s.assertSVIDsInUpdateLegacy(upd, workloadID)
	s.Equal(dnsList, chains[0][0].DNSNames)
	s.Equal("somehost1", chains[0][0].Subject.CommonName)
}

func (s *HandlerSuite) TestFetchX509SVIDWithMultipleDNS() {
	dnsList := []string{"somehost1", "somehost2", "somehost3"}

	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: workloadID,
		DnsNames: dnsList,
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

func (s *HandlerSuite) TestFetchX509SVIDWithMultipleDNSLegacy() {
	dnsList := []string{"somehost1", "somehost2", "somehost3"}

	s.attestAgent()

	entry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: workloadID,
		DnsNames: dnsList,
	})

	upd := s.requireFetchX509SVIDSuccess(&node.FetchX509SVIDRequest{
		DEPRECATEDCsrs: s.makeCSRsLegacy(workloadID),
	})

	s.Equal([]*common.RegistrationEntry{entry}, upd.RegistrationEntries)
	s.assertBundlesInUpdate(upd)
	chains := s.assertSVIDsInUpdateLegacy(upd, workloadID)
	s.Equal(dnsList, chains[0][0].DNSNames)
	s.Equal("somehost1", chains[0][0].Subject.CommonName)
}

func (s *HandlerSuite) TestFetchJWTSVIDWithUnattestedAgent() {
	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{},
		codes.PermissionDenied, "agent is not attested or no longer valid")
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
	}, codes.PermissionDenied, `caller "spiffe://example.org/spire/agent/test/id" is not authorized for "spiffe://example.org/spire/agent/test/id"`)
}

func (s *HandlerSuite) TestFetchJWTSVIDWithUnauthorizedSPIFFEID() {
	s.attestAgent()

	s.requireFetchJWTSVIDFailure(&node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: workloadID,
			Audience: []string{"audience"},
		},
	}, codes.PermissionDenied, `caller "spiffe://example.org/spire/agent/test/id" is not authorized for "spiffe://example.org/workload"`)
}

func (s *HandlerSuite) TestFetchJWTSVIDWithWorkloadID() {
	s.attestAgent()

	s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId: agentID,
		SpiffeId: workloadID,
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

	// no peer context
	ctx, err := s.handler.AuthorizeCall(context.Background(), fullMethod)
	s.RequireGRPCStatus(err, codes.Unauthenticated, "downstream SVID is required for this request")
	s.Require().Nil(ctx)
	s.assertLastLogMessage("no peer information")

	// non-TLS peer context
	ctx, err = s.handler.AuthorizeCall(peer.NewContext(context.Background(), &peer.Peer{}), fullMethod)
	s.RequireGRPCStatus(err, codes.Unauthenticated, "downstream SVID is required for this request")
	s.Require().Nil(ctx)
	s.assertLastLogMessage("no TLS auth info for peer")

	// no verified chains on TLS peer context
	ctx, err = s.handler.AuthorizeCall(peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{},
	}), fullMethod)
	s.RequireGRPCStatus(err, codes.Unauthenticated, "downstream SVID is required for this request")
	s.Require().Nil(ctx)
	s.assertLastLogMessage("no verified client certificate presented by peer")

	// no downstream registration entry
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, "peer is not a valid downstream SPIRE server")
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`"spiffe://example.org/downstream" is not an authorized downstream workload`)

	// good certificate
	downstreamEntry := s.createRegistrationEntry(&common.RegistrationEntry{
		ParentId:   agentID,
		SpiffeId:   downstreamID,
		Downstream: true,
	})
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.Require().NoError(err)

	actualCert, ok := getPeerCertificate(ctx)
	s.Require().True(ok, "context has peer certificate")
	s.Require().True(peerCert.Equal(actualCert), "peer certificate matches")

	actualEntry, ok := getDownstreamEntry(ctx)
	s.Require().True(ok, "context has downstream entry")
	s.RequireProtoEqual(downstreamEntry, actualEntry)

}

func (s *HandlerSuite) testAuthorizeCallRequiringAgentSVID(method string) {
	peerCert := s.agentSVID[0]
	peerCtx := withPeerCert(context.Background(), s.agentSVID)

	fullMethod := fmt.Sprintf("/spire.api.node.Node/%s", method)

	// no peer context
	ctx, err := s.handler.AuthorizeCall(context.Background(), fullMethod)
	s.RequireGRPCStatus(err, codes.Unauthenticated, "agent SVID is required for this request")
	s.Require().Nil(ctx)
	s.assertLastLogMessage("no peer information")

	// non-TLS peer context
	ctx, err = s.handler.AuthorizeCall(peer.NewContext(context.Background(), &peer.Peer{}), fullMethod)
	s.RequireGRPCStatus(err, codes.Unauthenticated, "agent SVID is required for this request")
	s.Require().Nil(ctx)
	s.assertLastLogMessage("no TLS auth info for peer")

	// no verified chains on TLS peer context
	ctx, err = s.handler.AuthorizeCall(peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{},
	}), fullMethod)
	s.RequireGRPCStatus(err, codes.Unauthenticated, "agent SVID is required for this request")
	s.Require().Nil(ctx)
	s.assertLastLogMessage("no verified client certificate presented by peer")

	// no attested certificate with matching SPIFFE ID
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, "agent is not attested or no longer valid")
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`agent "spiffe://example.org/spire/agent/test/id" is not attested`)

	// good certificate
	s.attestAgent()
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.Require().NoError(err)
	actualCert, ok := getPeerCertificate(ctx)
	s.Require().True(ok, "context has peer certificate")
	s.Require().True(peerCert.Equal(actualCert), "peer certificate matches")

	// expired certificate
	s.clock.Set(peerCert.NotAfter.Add(time.Second))
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, "agent is not attested or no longer valid")
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`agent "spiffe://example.org/spire/agent/test/id" SVID has expired`)
	s.clock.Set(peerCert.NotAfter)

	// serial number does not match
	s.updateAttestedNode(agentID, "SERIAL NUMBER", peerCert.NotAfter)
	ctx, err = s.handler.AuthorizeCall(peerCtx, fullMethod)
	s.RequireGRPCStatus(err, codes.PermissionDenied, "agent is not attested or no longer valid")
	s.Require().Nil(ctx)
	s.assertLastLogMessage(`agent "spiffe://example.org/spire/agent/test/id" SVID does not match expected serial number`)
}

func (s *HandlerSuite) addAttestor(name string, config fakeservernodeattestor.Config) {
	var p nodeattestor.NodeAttestor
	s.LoadPlugin(catalog.MakePlugin(name, nodeattestor.PluginServer(fakeservernodeattestor.New(name, config))), &p)
	s.catalog.AddNodeAttestorNamed(name, p)
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

func (s *HandlerSuite) fetchAttestedNode(spiffeID string) *common.AttestedNode {
	resp, err := s.ds.FetchAttestedNode(context.Background(), &datastore.FetchAttestedNodeRequest{
		SpiffeId: spiffeID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	return resp.Node
}

func (s *HandlerSuite) getNodeSelectors(spiffeID string) []*common.Selector {
	resp, err := s.ds.GetNodeSelectors(context.Background(), &datastore.GetNodeSelectorsRequest{
		SpiffeId: spiffeID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Selectors)
	s.Require().Equal(spiffeID, resp.Selectors.SpiffeId)
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
	telemetry_common.AddSPIFFEID(expectedCounter, expectedSPIFFE)

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
	stream.CloseSend()
	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.SvidUpdate)

	// ensure end of stream so server-side telemetry is done
	eofResp, err := stream.Recv()
	s.Require().Nil(eofResp)
	s.Require().Equal(io.EOF, err)

	return resp.SvidUpdate
}

func (s *HandlerSuite) requireAttestFailure(req *node.AttestRequest, expectedSPIFFE string, errorCode codes.Code, errorContains string) {
	expectedCounter := telemetry_server.StartNodeAPIAttestCall(s.expectedMetrics)
	if req.AttestationData != nil && req.AttestationData.Type != "" {
		telemetry_common.AddAttestorType(expectedCounter, req.AttestationData.Type)
	}
	if expectedSPIFFE != "" {
		telemetry_common.AddSPIFFEID(expectedCounter, expectedSPIFFE)
	}
	fakeErr := errors.New("")
	defer expectedCounter.Done(&fakeErr)
	defer expectedCounter.AddLabel(telemetry.Error, errorCode.String())

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.unattestedClient.Attest(ctx)
	s.Require().NoError(err)
	s.Require().NoError(stream.Send(req))
	stream.CloseSend()
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
	stream.CloseSend()
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
	stream.CloseSend()
	resp, err := stream.Recv()
	s.Require().Contains(errorContains, status.Convert(err).Message())
	s.Require().Equal(errorCode, status.Code(err))
	s.Require().Nil(resp)
}

func (s *HandlerSuite) requireFetchX509SVIDAuthFailure() {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := s.attestedClient.FetchX509SVID(ctx)
	s.Require().NoError(err)
	// the auth failure will come back on the Recv(). we shouldn't have to send
	// on the stream to get this to happen.
	resp, err := stream.Recv()
	s.Require().Contains("agent is not attested or no longer valid", status.Convert(err).Message())
	s.Require().Equal(codes.PermissionDenied, status.Code(err))
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
	s.Require().Contains(errorContains, status.Convert(err).Message())
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

func (s *HandlerSuite) assertSVIDsInUpdateLegacy(upd *node.X509SVIDUpdate, spiffeIDs ...string) [][]*x509.Certificate {
	s.Len(upd.Svids, len(spiffeIDs), "number of SVIDs in update")

	var svidChains [][]*x509.Certificate
	for _, spiffeID := range spiffeIDs {
		svidEntry := upd.Svids[spiffeID]
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

func (s *HandlerSuite) assertLastLogMessage(message string) {
	entry := s.logHook.LastEntry()
	if s.NotNil(entry) {
		s.Equal(message, entry.Message)
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

func (s *HandlerSuite) makeCSRsLegacy(spiffeIDs ...string) [][]byte {
	var csrs [][]byte
	for _, spiffeID := range spiffeIDs {
		csrs = append(csrs, s.makeCSR(spiffeID))
	}
	return csrs
}

func (s *HandlerSuite) makeCSRs(entryID, spiffeID string) map[string][]byte {
	csrs := make(map[string][]byte)
	csrs[entryID] = s.makeCSR(spiffeID)
	return csrs
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
