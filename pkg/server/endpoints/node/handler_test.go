package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeupstreamca"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/server/noderesolver"
	"github.com/spiffe/spire/test/mock/server/ca"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	testTrustDomain = url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}
)

type HandlerTestSuite struct {
	suite.Suite
	ctrl             *gomock.Controller
	handler          *Handler
	limiter          *fakeLimiter
	mockDataStore    *mock_datastore.MockDataStore
	mockServerCA     *mock_ca.MockServerCA
	mockNodeAttestor *mock_nodeattestor.MockNodeAttestor
	mockNodeResolver *mock_noderesolver.MockNodeResolver
	server           *mock_node.MockNode_FetchX509SVIDServer
	now              time.Time
}

func SetupHandlerTest(t *testing.T) *HandlerTestSuite {
	suite := &HandlerTestSuite{}
	suite.SetT(t)
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, _ := test.NewNullLogger()
	suite.limiter = new(fakeLimiter)
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)
	suite.mockServerCA = mock_ca.NewMockServerCA(mockCtrl)
	suite.mockNodeAttestor = mock_nodeattestor.NewMockNodeAttestor(mockCtrl)
	suite.mockNodeResolver = mock_noderesolver.NewMockNodeResolver(mockCtrl)
	suite.server = mock_node.NewMockNode_FetchX509SVIDServer(suite.ctrl)
	suite.now = time.Now()

	catalog := fakeservercatalog.New()
	catalog.SetDataStores(suite.mockDataStore)
	catalog.SetNodeAttestors(suite.mockNodeAttestor)
	catalog.SetNodeResolvers(suite.mockNodeResolver)

	suite.handler = NewHandler(HandlerConfig{
		Log:         log,
		Catalog:     catalog,
		ServerCA:    suite.mockServerCA,
		TrustDomain: testTrustDomain,
	})
	suite.handler.hooks.now = func() time.Time {
		return suite.now
	}
	suite.handler.limiter = suite.limiter
	return suite
}

func TestAttest(t *testing.T) {
	suite := SetupHandlerTest(t)
	defer suite.ctrl.Finish()

	ctx := peer.NewContext(context.Background(), getFakePeer())
	data := getAttestTestData()

	stream := mock_node.NewMockNode_AttestServer(suite.ctrl)
	stream.EXPECT().Context().Return(ctx).AnyTimes()
	stream.EXPECT().Recv().Return(data.request, nil).AnyTimes()

	expected := getExpectedAttest(suite, data.baseSpiffeID, data.generatedCert)
	stream.EXPECT().Send(&node.AttestResponse{
		SvidUpdate: expected,
	}).AnyTimes()

	setAttestExpectations(suite, data)
	suite.NoError(suite.handler.Attest(stream))
	suite.Equal(1, suite.limiter.callsFor(AttestMsg))
}

func TestAttestChallengeResponse(t *testing.T) {
	suite := SetupHandlerTest(t)
	defer suite.ctrl.Finish()

	data := getAttestTestData()
	data.challenges = []challengeResponse{
		{challenge: "1+1", response: "2"},
		{challenge: "5+7", response: "12"},
	}
	setAttestExpectations(suite, data)

	expected := getExpectedAttest(suite, data.baseSpiffeID, data.generatedCert)

	ctx := peer.NewContext(context.Background(), getFakePeer())
	stream := mock_node.NewMockNode_AttestServer(suite.ctrl)
	stream.EXPECT().Context().Return(ctx)
	stream.EXPECT().Recv().Return(data.request, nil)
	stream.EXPECT().Send(&node.AttestResponse{
		Challenge: []byte("1+1"),
	})
	challenge1 := *data.request
	challenge1.Response = []byte("2")
	stream.EXPECT().Recv().Return(&challenge1, nil)
	stream.EXPECT().Send(&node.AttestResponse{
		Challenge: []byte("5+7"),
	})
	challenge2 := *data.request
	challenge2.Response = []byte("12")
	stream.EXPECT().Recv().Return(&challenge2, nil)
	stream.EXPECT().Send(&node.AttestResponse{
		SvidUpdate: expected,
	})
	suite.NoError(suite.handler.Attest(stream))
}

func TestFetchX509SVID(t *testing.T) {
	suite := SetupHandlerTest(t)
	defer suite.ctrl.Finish()

	data := getFetchX509SVIDTestData()
	data.expectation = getExpectedFetchX509SVID(data)
	setFetchX509SVIDExpectations(suite, data)

	err := suite.handler.FetchX509SVID(suite.server)
	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

	limiterCalls := suite.limiter.callsFor(CSRMsg)
	if len(data.request.Csrs) != limiterCalls {
		t.Errorf("expected %v calls to limiter; got %v", len(data.request.Csrs), limiterCalls)
	}
}

func TestFetchX509SVIDWithRotation(t *testing.T) {
	suite := SetupHandlerTest(t)
	defer suite.ctrl.Finish()

	data := getFetchX509SVIDTestData()
	data.request.Csrs = append(
		data.request.Csrs, getBytesFromPem("base_rotated_csr.pem"))
	data.generatedCerts = append(
		data.generatedCerts, loadCertFromPEM("base_rotated_cert.pem"))

	// Calculate expected TTL
	cert := data.generatedCerts[3]

	data.expectation = getExpectedFetchX509SVID(data)
	data.expectation.Svids[data.baseSpiffeID] = makeX509SVID(cert)
	setFetchX509SVIDExpectations(suite, data)

	suite.mockDataStore.EXPECT().FetchAttestedNode(gomock.Any(),
		&datastore.FetchAttestedNodeRequest{SpiffeId: data.baseSpiffeID},
	).
		Return(&datastore.FetchAttestedNodeResponse{
			Node: &datastore.AttestedNode{
				CertSerialNumber: "18392437442709699290",
			},
		}, nil)

	suite.mockServerCA.EXPECT().
		SignX509SVID(gomock.Any(), data.request.Csrs[3], time.Duration(0)).Return(cert, nil)

	suite.mockDataStore.EXPECT().
		UpdateAttestedNode(gomock.Any(), gomock.Any()).
		Return(&datastore.UpdateAttestedNodeResponse{}, nil)

	err := suite.handler.FetchX509SVID(suite.server)
	suite.Require().NoError(err)
}

func loadCertFromPEM(fileName string) *x509.Certificate {
	certDER := getBytesFromPem(fileName)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func getBytesFromPem(fileName string) []byte {
	pemFile, _ := ioutil.ReadFile(path.Join("../../../../test/fixture/certs", fileName))
	decodedFile, _ := pem.Decode(pemFile)
	return decodedFile.Bytes
}

type challengeResponse struct {
	challenge string
	response  string
}

type fetchBaseSVIDData struct {
	request                 *node.AttestRequest
	generatedCert           *x509.Certificate
	baseSpiffeID            string
	selector                *common.Selector
	selectors               map[string]*common.Selectors
	attestResponseSelectors []*common.Selector
	regEntryParentIDList    []*common.RegistrationEntry
	regEntrySelectorList    []*common.RegistrationEntry
	challenges              []challengeResponse
}

func getAttestTestData() *fetchBaseSVIDData {
	data := &fetchBaseSVIDData{}

	data.request = &node.AttestRequest{
		Csr: getBytesFromPem("base_csr.pem"),
		AttestationData: &common.AttestationData{
			Type: "fake_nodeattestor_1",
			Data: []byte("fake attestation data"),
		},
	}

	data.generatedCert = loadCertFromPEM("base_cert.pem")

	data.baseSpiffeID = "spiffe://example.org/spire/agent/join_token/token"
	data.selector = &common.Selector{Type: "foo", Value: "bar"}
	data.selectors = make(map[string]*common.Selectors)
	data.selectors[data.baseSpiffeID] = &common.Selectors{
		Entries: []*common.Selector{data.selector},
	}

	data.regEntryParentIDList = []*common.RegistrationEntry{
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test1"},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"}}

	data.regEntrySelectorList = []*common.RegistrationEntry{
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test2",
		},
	}

	data.attestResponseSelectors = []*common.Selector{
		{Type: "type1", Value: "value1"},
		{Type: "type2", Value: "value2"},
	}
	return data
}

func setAttestExpectations(
	suite *HandlerTestSuite, data *fetchBaseSVIDData) {

	stream := mock_nodeattestor.NewMockAttest_Stream(suite.ctrl)
	stream.EXPECT().Send(&nodeattestor.AttestRequest{
		AttestedBefore:  false,
		AttestationData: data.request.AttestationData,
	})
	for _, challenge := range data.challenges {
		stream.EXPECT().Recv().Return(&nodeattestor.AttestResponse{
			Challenge: []byte(challenge.challenge),
		}, nil)
		stream.EXPECT().Send(&nodeattestor.AttestRequest{
			AttestedBefore:  false,
			AttestationData: data.request.AttestationData,
			Response:        []byte(challenge.response),
		})
	}
	stream.EXPECT().Recv().Return(&nodeattestor.AttestResponse{
		BaseSPIFFEID: data.baseSpiffeID,
		Valid:        true,
		Selectors:    data.attestResponseSelectors,
	}, nil)
	stream.EXPECT().CloseSend()
	stream.EXPECT().Recv().Return(nil, io.EOF)

	suite.mockNodeAttestor.EXPECT().Attest(gomock.Any()).Return(stream, nil)

	suite.mockDataStore.EXPECT().FetchAttestedNode(gomock.Any(),
		&datastore.FetchAttestedNodeRequest{
			SpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.FetchAttestedNodeResponse{Node: nil}, nil)

	suite.mockServerCA.EXPECT().SignX509SVID(
		gomock.Any(), data.request.Csr, time.Duration(0)).Return(data.generatedCert, nil)

	suite.mockDataStore.EXPECT().CreateAttestedNode(gomock.Any(),
		&datastore.CreateAttestedNodeRequest{
			Node: &datastore.AttestedNode{
				AttestationDataType: "fake_nodeattestor_1",
				SpiffeId:            data.baseSpiffeID,
				CertNotAfter:        1822684794,
				CertSerialNumber:    "18392437442709699290",
			}}).
		Return(nil, nil)

	suite.mockNodeResolver.EXPECT().Resolve(gomock.Any(),
		&noderesolver.ResolveRequest{
			BaseSpiffeIdList: []string{data.baseSpiffeID},
		}).
		Return(&noderesolver.ResolveResponse{
			Map: data.selectors,
		}, nil)

	suite.mockDataStore.EXPECT().SetNodeSelectors(gomock.Any(),
		&datastore.SetNodeSelectorsRequest{
			Selectors: &datastore.NodeSelectors{
				SpiffeId: data.baseSpiffeID,
				Selectors: []*common.Selector{
					data.selector,
					data.attestResponseSelectors[0],
					data.attestResponseSelectors[1],
				},
			},
		}).
		Return(nil, nil)

	// begin FetchRegistrationEntries(baseSpiffeID)

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(),
			&datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
					Value: data.baseSpiffeID,
				},
			}).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: data.regEntryParentIDList}, nil)

	suite.mockDataStore.EXPECT().
		GetNodeSelectors(gomock.Any(), &datastore.GetNodeSelectorsRequest{
			SpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.GetNodeSelectorsResponse{
			Selectors: &datastore.NodeSelectors{
				SpiffeId:  data.baseSpiffeID,
				Selectors: []*common.Selector{data.selector},
			},
		}, nil)

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{
			BySelectors: &datastore.BySelectors{
				Selectors: []*common.Selector{data.selector},
				Match:     datastore.BySelectors_MATCH_SUBSET,
			},
		}).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: data.regEntrySelectorList,
		}, nil)

	for _, entry := range data.regEntryParentIDList {
		suite.mockDataStore.EXPECT().
			ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
					Value: entry.SpiffeId,
				},
			}).
			Return(&datastore.ListRegistrationEntriesResponse{}, nil)
		suite.mockDataStore.EXPECT().
			GetNodeSelectors(gomock.Any(), &datastore.GetNodeSelectorsRequest{
				SpiffeId: entry.SpiffeId,
			}).
			Return(&datastore.GetNodeSelectorsResponse{
				Selectors: &datastore.NodeSelectors{
					SpiffeId: entry.SpiffeId,
				},
			}, nil)
	}

	// none of the selector entries have children or node resolver entries.
	// the "repeated" entry is not expected to be processed again since it was
	// already processed as a child.
	for _, entry := range data.regEntrySelectorList {
		if entry.SpiffeId == "spiffe://repeated" {
			continue
		}
		suite.mockDataStore.EXPECT().
			ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
					Value: entry.SpiffeId,
				},
			}).
			Return(&datastore.ListRegistrationEntriesResponse{}, nil)
		suite.mockDataStore.EXPECT().
			GetNodeSelectors(gomock.Any(), &datastore.GetNodeSelectorsRequest{
				SpiffeId: entry.SpiffeId,
			}).
			Return(&datastore.GetNodeSelectorsResponse{
				Selectors: &datastore.NodeSelectors{
					SpiffeId: entry.SpiffeId,
				},
			}, nil)
	}

	// end FetchRegistrationEntries(baseSpiffeID)

	caCert, _, err := util.LoadCAFixture()
	require.NoError(suite.T(), err)

	suite.mockDataStore.EXPECT().
		FetchBundle(gomock.Any(), &datastore.FetchBundleRequest{
			TrustDomain: testTrustDomain.String()}).
		Return(&datastore.FetchBundleResponse{
			Bundle: &datastore.Bundle{
				TrustDomain: testTrustDomain.String(),
				CaCerts:     caCert.Raw,
			},
		}, nil)
}

func getExpectedAttest(suite *HandlerTestSuite, baseSpiffeID string, cert *x509.Certificate) *node.X509SVIDUpdate {
	expectedRegEntries := []*common.RegistrationEntry{
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated",
		},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test1",
		},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test2",
		},
	}

	svids := make(map[string]*node.X509SVID)
	svids[baseSpiffeID] = makeX509SVID(cert)

	caCert, _, _ := util.LoadCAFixture()
	svidUpdate := &node.X509SVIDUpdate{
		Svids:               svids,
		Bundle:              caCert.Raw,
		RegistrationEntries: expectedRegEntries,
	}

	return svidUpdate
}

type fetchSVIDData struct {
	request            *node.FetchX509SVIDRequest
	baseSpiffeID       string
	nodeSpiffeID       string
	databaseSpiffeID   string
	blogSpiffeID       string
	generatedCerts     []*x509.Certificate
	selector           *common.Selector
	spiffeIDs          []string
	nodeSelectors      []*common.Selector
	bySelectorsEntries []*common.RegistrationEntry
	byParentIDEntries  []*common.RegistrationEntry
	expectation        *node.X509SVIDUpdate
}

func getFetchX509SVIDTestData() *fetchSVIDData {
	data := &fetchSVIDData{}
	data.spiffeIDs = []string{
		"spiffe://example.org/database",
		"spiffe://example.org/blog",
		"spiffe://example.org/spire/agent/join_token/tokenfoo",
	}
	data.baseSpiffeID = "spiffe://example.org/spire/agent/join_token/token"
	//TODO: get rid of this
	data.nodeSpiffeID = "spiffe://example.org/spire/agent/join_token/tokenfoo"
	data.databaseSpiffeID = "spiffe://example.org/database"
	data.blogSpiffeID = "spiffe://example.org/blog"

	data.request = &node.FetchX509SVIDRequest{}
	data.request.Csrs = [][]byte{
		getBytesFromPem("node_csr.pem"),
		getBytesFromPem("database_csr.pem"),
		getBytesFromPem("blog_csr.pem"),
	}

	data.generatedCerts = []*x509.Certificate{
		loadCertFromPEM("node_cert.pem"),
		loadCertFromPEM("database_cert.pem"),
		loadCertFromPEM("blog_cert.pem"),
	}

	data.selector = &common.Selector{Type: "foo", Value: "bar"}
	data.nodeSelectors = []*common.Selector{data.selector}

	data.bySelectorsEntries = []*common.RegistrationEntry{
		{SpiffeId: data.baseSpiffeID, Ttl: 1111},
	}

	data.byParentIDEntries = []*common.RegistrationEntry{
		{SpiffeId: data.spiffeIDs[0], Ttl: 2222},
		{SpiffeId: data.spiffeIDs[1], Ttl: 3333},
		{SpiffeId: data.spiffeIDs[2], Ttl: 4444},
	}

	return data
}

func setFetchX509SVIDExpectations(
	suite *HandlerTestSuite, data *fetchSVIDData) {

	caCert, _, err := util.LoadCAFixture()
	require.NoError(suite.T(), err)

	ctx := peer.NewContext(context.Background(), getFakePeer())
	suite.server.EXPECT().Context().Return(ctx)
	suite.server.EXPECT().Recv().Return(data.request, nil)

	// begin FetchRegistrationEntries()

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(),
			&datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
					Value: data.baseSpiffeID,
				},
			}).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: data.byParentIDEntries}, nil)

	suite.mockDataStore.EXPECT().
		GetNodeSelectors(gomock.Any(), &datastore.GetNodeSelectorsRequest{
			SpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.GetNodeSelectorsResponse{
			Selectors: &datastore.NodeSelectors{
				SpiffeId:  data.baseSpiffeID,
				Selectors: data.nodeSelectors,
			},
		}, nil)

	suite.mockDataStore.EXPECT().
		ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{
			BySelectors: &datastore.BySelectors{
				Selectors: []*common.Selector{data.selector},
				Match:     datastore.BySelectors_MATCH_SUBSET,
			},
		}).
		Return(&datastore.ListRegistrationEntriesResponse{
			Entries: data.bySelectorsEntries,
		}, nil)

	for _, entry := range data.byParentIDEntries {
		suite.mockDataStore.EXPECT().
			ListRegistrationEntries(gomock.Any(), &datastore.ListRegistrationEntriesRequest{
				ByParentId: &wrappers.StringValue{
					Value: entry.SpiffeId,
				},
			}).
			Return(&datastore.ListRegistrationEntriesResponse{}, nil)
		suite.mockDataStore.EXPECT().
			GetNodeSelectors(gomock.Any(), &datastore.GetNodeSelectorsRequest{
				SpiffeId: entry.SpiffeId,
			}).
			Return(&datastore.GetNodeSelectorsResponse{
				Selectors: &datastore.NodeSelectors{
					SpiffeId: entry.SpiffeId,
				},
			}, nil)
	}

	// end FetchRegistrationEntries(baseSpiffeID)

	suite.mockDataStore.EXPECT().
		FetchBundle(gomock.Any(), &datastore.FetchBundleRequest{
			TrustDomain: testTrustDomain.String()}).
		Return(&datastore.FetchBundleResponse{
			Bundle: &datastore.Bundle{
				TrustDomain: testTrustDomain.String(),
				CaCerts:     caCert.Raw,
			},
		}, nil)

	suite.mockServerCA.EXPECT().SignX509SVID(gomock.Any(),
		data.request.Csrs[0], durationFromTTL(data.byParentIDEntries[2].Ttl)).Return(data.generatedCerts[0], nil)

	suite.mockServerCA.EXPECT().SignX509SVID(gomock.Any(),
		data.request.Csrs[1], durationFromTTL(data.byParentIDEntries[0].Ttl)).Return(data.generatedCerts[1], nil)

	suite.mockServerCA.EXPECT().SignX509SVID(gomock.Any(),
		data.request.Csrs[2], durationFromTTL(data.byParentIDEntries[1].Ttl)).Return(data.generatedCerts[2], nil)

	suite.server.EXPECT().Send(&node.FetchX509SVIDResponse{
		SvidUpdate: data.expectation,
	}).
		Return(nil)

	suite.server.EXPECT().Recv().Return(nil, io.EOF)

}

func getExpectedFetchX509SVID(data *fetchSVIDData) *node.X509SVIDUpdate {
	//TODO: improve this, put it in an array in data and iterate it
	svids := map[string]*node.X509SVID{
		data.nodeSpiffeID:     makeX509SVID(data.generatedCerts[0]),
		data.databaseSpiffeID: makeX509SVID(data.generatedCerts[1]),
		data.blogSpiffeID:     makeX509SVID(data.generatedCerts[2]),
	}

	// returned in sorted order (according to sorting rules in util.SortRegistrationEntries)
	registrationEntries := []*common.RegistrationEntry{
		data.byParentIDEntries[1],
		data.byParentIDEntries[0],
		data.bySelectorsEntries[0],
		data.byParentIDEntries[2],
	}

	caCert, _, _ := util.LoadCAFixture()
	svidUpdate := &node.X509SVIDUpdate{
		Svids:               svids,
		Bundle:              caCert.Raw,
		RegistrationEntries: registrationEntries,
	}

	return svidUpdate
}

func getFakePeer() *peer.Peer {
	parsedCert := loadCertFromPEM("base_cert.pem")

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parsedCert},
	}

	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	fakePeer := &peer.Peer{
		Addr:     addr,
		AuthInfo: credentials.TLSInfo{State: state},
	}

	return fakePeer
}

func durationFromTTL(ttl int32) time.Duration {
	return time.Duration(ttl) * time.Second
}

func TestFetchJWTSVID(t *testing.T) {
	ctx := peer.NewContext(context.Background(), getFakePeer())
	log, _ := test.NewNullLogger()

	dataStore := fakedatastore.New()
	dataStore.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &node.RegistrationEntry{
			ParentId: "spiffe://example.org/spire/agent/join_token/token",
			SpiffeId: "spiffe://example.org/blog",
			Ttl:      1,
		},
	})

	upstreamCA := fakeupstreamca.New(t, "localhost")
	serverCA := fakeserverca.New(t, "example.org", nil, time.Minute)

	catalog := fakeservercatalog.New()
	catalog.SetUpstreamCAs(upstreamCA)
	catalog.SetDataStores(dataStore)

	handler := NewHandler(HandlerConfig{
		Catalog:  catalog,
		ServerCA: serverCA,
		Log:      log,
	})

	limiter := new(fakeLimiter)
	handler.limiter = limiter

	// no peer certificate on context
	badPeer := getFakePeer()
	badPeer.AuthInfo = nil
	badCtx := peer.NewContext(context.Background(), badPeer)
	resp, err := handler.FetchJWTSVID(badCtx, &node.FetchJWTSVIDRequest{})
	require.Equal(t, 1, limiter.callsFor(JSRMsg))
	require.EqualError(t, err, "client SVID is required for this request")
	require.Nil(t, resp)

	// missing JSR
	resp, err = handler.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{})
	require.EqualError(t, err, "request missing JSR")
	require.Nil(t, resp)

	// missing SPIFFE ID
	resp, err = handler.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{},
	})
	require.EqualError(t, err, "request missing SPIFFE ID")
	require.Nil(t, resp)

	// missing audiences
	resp, err = handler.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: "spiffe://example.org/blog",
		},
	})
	require.EqualError(t, err, "request missing audience")
	require.Nil(t, resp)

	// not authorized for workload
	resp, err = handler.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: "spiffe://example.org/db",
			Audience: []string{"AUDIENCE"},
		},
	})
	require.EqualError(t, err, `caller "spiffe://example.org/spire/agent/join_token/token" is not authorized for "spiffe://example.org/db"`)
	require.Nil(t, resp)

	// authorized for ones self
	resp, err = handler.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: "spiffe://example.org/spire/agent/join_token/token",
			Audience: []string{"AUDIENCE"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Svid.Token)
	require.NotEqual(t, 0, resp.Svid.ExpiresAt)

	// authorized against a registration entry
	resp, err = handler.FetchJWTSVID(ctx, &node.FetchJWTSVIDRequest{
		Jsr: &node.JSR{
			SpiffeId: "spiffe://example.org/blog",
			Audience: []string{"AUDIENCE"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Svid.Token)
	require.NotEqual(t, 0, resp.Svid.ExpiresAt)
}

type fakeLimiter struct {
	callsForAttest int
	callsForCSR    int
	callsForJSR    int

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

	return nil
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
