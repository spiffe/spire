package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/mock/common/context"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/server/noderesolver"
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
	t                *testing.T
	ctrl             *gomock.Controller
	handler          *Handler
	mockDataStore    *mock_datastore.MockDataStore
	mockServerCA     *mock_ca.MockServerCA
	mockNodeAttestor *mock_nodeattestor.MockNodeAttestor
	mockNodeResolver *mock_noderesolver.MockNodeResolver
	mockContext      *mock_context.MockContext
	server           *mock_node.MockNode_FetchX509SVIDServer
	now              time.Time
}

func SetupHandlerTest(t *testing.T) *HandlerTestSuite {
	suite := &HandlerTestSuite{}
	suite.SetT(t)
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, _ := test.NewNullLogger()
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)
	suite.mockServerCA = mock_ca.NewMockServerCA(mockCtrl)
	suite.mockNodeAttestor = mock_nodeattestor.NewMockNodeAttestor(mockCtrl)
	suite.mockNodeResolver = mock_noderesolver.NewMockNodeResolver(mockCtrl)
	suite.mockContext = mock_context.NewMockContext(mockCtrl)
	suite.server = mock_node.NewMockNode_FetchX509SVIDServer(suite.ctrl)
	suite.now = time.Now()

	catalog := fakeservercatalog.New()
	catalog.SetDataStores(suite.mockDataStore)
	catalog.SetCAs(suite.mockServerCA)
	catalog.SetNodeAttestors(suite.mockNodeAttestor)
	catalog.SetNodeResolvers(suite.mockNodeResolver)

	suite.handler = NewHandler(HandlerConfig{
		Log:         log,
		Catalog:     catalog,
		TrustDomain: testTrustDomain,
	})
	suite.handler.hooks.now = func() time.Time {
		return suite.now
	}
	return suite
}

func TestAttest(t *testing.T) {
	suite := SetupHandlerTest(t)
	defer suite.ctrl.Finish()

	data := getAttestTestData()
	setAttestExpectations(suite, data)

	expected := getExpectedAttest(suite, data.baseSpiffeID, data.generatedCert)

	stream := mock_node.NewMockNode_AttestServer(suite.ctrl)
	stream.EXPECT().Context().Return(context.Background())
	stream.EXPECT().Recv().Return(data.request, nil)

	stream.EXPECT().Send(&node.AttestResponse{
		SvidUpdate: expected,
	})
	suite.NoError(suite.handler.Attest(stream))
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

	stream := mock_node.NewMockNode_AttestServer(suite.ctrl)
	stream.EXPECT().Context().Return(context.Background())
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

}

func TestFetchX509SVIDWithRotation(t *testing.T) {
	suite := SetupHandlerTest(t)
	defer suite.ctrl.Finish()

	data := getFetchX509SVIDTestData()
	data.request.Csrs = append(
		data.request.Csrs, getBytesFromPem("base_rotated_csr.pem"))
	data.generatedCerts = append(
		data.generatedCerts, getBytesFromPem("base_rotated_cert.pem"))

	// Calculate expected TTL
	cert, err := x509.ParseCertificate(data.generatedCerts[3])
	require.NoError(t, err)
	ttl := int32(cert.NotAfter.Sub(suite.now).Seconds())

	data.expectation = getExpectedFetchX509SVID(data)
	data.expectation.Svids[data.baseSpiffeID] = &node.Svid{SvidCert: data.generatedCerts[3], Ttl: ttl}
	setFetchX509SVIDExpectations(suite, data)

	suite.mockDataStore.EXPECT().FetchAttestedNodeEntry(gomock.Any(),
		&datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: data.baseSpiffeID},
	).
		Return(&datastore.FetchAttestedNodeEntryResponse{
			AttestedNodeEntry: &datastore.AttestedNodeEntry{
				CertSerialNumber: "18392437442709699290",
			},
		}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(gomock.Any(), &ca.SignCsrRequest{
			Csr: data.request.Csrs[3],
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[3]}, nil)

	suite.mockDataStore.EXPECT().
		UpdateAttestedNodeEntry(gomock.Any(), gomock.Any()).
		Return(&datastore.UpdateAttestedNodeEntryResponse{}, nil)

	err = suite.handler.FetchX509SVID(suite.server)

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

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
	request              *node.AttestRequest
	generatedCert        []byte
	baseSpiffeID         string
	selector             *common.Selector
	selectors            map[string]*common.Selectors
	regEntryParentIDList []*common.RegistrationEntry
	regEntrySelectorList []*common.RegistrationEntry
	challenges           []challengeResponse
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

	data.generatedCert = getBytesFromPem("base_cert.pem")

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
	}, nil)
	stream.EXPECT().CloseSend()
	stream.EXPECT().Recv().Return(nil, io.EOF)

	suite.mockNodeAttestor.EXPECT().Attest(gomock.Any()).Return(stream, nil)

	suite.mockDataStore.EXPECT().FetchAttestedNodeEntry(gomock.Any(),
		&datastore.FetchAttestedNodeEntryRequest{
			BaseSpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.FetchAttestedNodeEntryResponse{AttestedNodeEntry: nil}, nil)

	suite.mockServerCA.EXPECT().SignCsr(gomock.Any(), &ca.SignCsrRequest{
		Csr: data.request.Csr,
	}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCert}, nil)

	suite.mockDataStore.EXPECT().CreateAttestedNodeEntry(gomock.Any(),
		&datastore.CreateAttestedNodeEntryRequest{
			AttestedNodeEntry: &datastore.AttestedNodeEntry{
				AttestationDataType: "fake_nodeattestor_1",
				BaseSpiffeId:        data.baseSpiffeID,
				CertExpirationDate:  "Mon, 04 Oct 2027 21:19:54 +0000",
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

	suite.mockDataStore.EXPECT().CreateNodeResolverMapEntry(gomock.Any(),
		&datastore.CreateNodeResolverMapEntryRequest{
			NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
				BaseSpiffeId: data.baseSpiffeID,
				Selector:     data.selector,
			},
		}).
		Return(nil, nil)

	// begin FetchRegistrationEntries(baseSpiffeID)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(gomock.Any(),
			&datastore.ListParentIDEntriesRequest{ParentId: data.baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{
			RegisteredEntryList: data.regEntryParentIDList}, nil)

	suite.mockDataStore.EXPECT().
		FetchNodeResolverMapEntry(gomock.Any(), &datastore.FetchNodeResolverMapEntryRequest{
			BaseSpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.FetchNodeResolverMapEntryResponse{
			NodeResolverMapEntryList: []*datastore.NodeResolverMapEntry{
				{BaseSpiffeId: data.baseSpiffeID, Selector: data.selector},
			},
		}, nil)

	suite.mockDataStore.EXPECT().
		ListMatchingEntries(gomock.Any(), &datastore.ListSelectorEntriesRequest{
			Selectors: []*common.Selector{data.selector},
		}).
		Return(&datastore.ListSelectorEntriesResponse{
			RegisteredEntryList: data.regEntrySelectorList,
		}, nil)

	for _, entry := range data.regEntryParentIDList {
		suite.mockDataStore.EXPECT().
			ListParentIDEntries(gomock.Any(), &datastore.ListParentIDEntriesRequest{
				ParentId: entry.SpiffeId}).
			Return(&datastore.ListParentIDEntriesResponse{}, nil)
		suite.mockDataStore.EXPECT().
			FetchNodeResolverMapEntry(gomock.Any(), &datastore.FetchNodeResolverMapEntryRequest{
				BaseSpiffeId: entry.SpiffeId,
			}).
			Return(&datastore.FetchNodeResolverMapEntryResponse{}, nil)
	}

	// none of the selector entries have children or node resolver entries.
	// the "repeated" entry is not expected to be processed again since it was
	// already processed as a child.
	for _, entry := range data.regEntrySelectorList {
		if entry.SpiffeId == "spiffe://repeated" {
			continue
		}
		suite.mockDataStore.EXPECT().
			ListParentIDEntries(gomock.Any(), &datastore.ListParentIDEntriesRequest{
				ParentId: entry.SpiffeId}).
			Return(&datastore.ListParentIDEntriesResponse{}, nil)
		suite.mockDataStore.EXPECT().
			FetchNodeResolverMapEntry(gomock.Any(), &datastore.FetchNodeResolverMapEntryRequest{
				BaseSpiffeId: entry.SpiffeId,
			}).
			Return(&datastore.FetchNodeResolverMapEntryResponse{}, nil)
	}

	// end FetchRegistrationEntries(baseSpiffeID)

	caCert, _, err := util.LoadCAFixture()
	require.NoError(suite.T(), err)

	suite.mockDataStore.EXPECT().
		FetchBundle(gomock.Any(), &datastore.Bundle{
			TrustDomain: testTrustDomain.String()}).
		Return(&datastore.Bundle{
			TrustDomain: testTrustDomain.String(),
			CaCerts:     caCert.Raw}, nil)
}

func getExpectedAttest(suite *HandlerTestSuite, baseSpiffeID string, cert []byte) *node.SvidUpdate {
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

	// Calculate expected TTL
	c, _ := x509.ParseCertificate(cert)
	ttl := int32(c.NotAfter.Sub(suite.now).Seconds())

	svids := make(map[string]*node.Svid)
	svids[baseSpiffeID] = &node.Svid{SvidCert: cert, Ttl: ttl}

	caCert, _, _ := util.LoadCAFixture()
	svidUpdate := &node.SvidUpdate{
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
	generatedCerts     [][]byte
	selector           *common.Selector
	spiffeIDs          []string
	nodeResolutionList []*datastore.NodeResolverMapEntry
	bySelectorsEntries []*common.RegistrationEntry
	byParentIDEntries  []*common.RegistrationEntry
	expectation        *node.SvidUpdate
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

	data.generatedCerts = [][]byte{
		getBytesFromPem("node_cert.pem"),
		getBytesFromPem("database_cert.pem"),
		getBytesFromPem("blog_cert.pem"),
	}

	data.selector = &common.Selector{Type: "foo", Value: "bar"}
	data.nodeResolutionList = []*datastore.NodeResolverMapEntry{
		{
			BaseSpiffeId: data.baseSpiffeID,
			Selector:     data.selector,
		},
	}

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

	suite.server.EXPECT().Context().Return(suite.mockContext)
	suite.server.EXPECT().Recv().Return(data.request, nil)

	suite.mockContext.EXPECT().Value(gomock.Any()).Return(getFakePeer())

	// begin FetchRegistrationEntries()

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(gomock.Any(),
			&datastore.ListParentIDEntriesRequest{ParentId: data.baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{
			RegisteredEntryList: data.byParentIDEntries}, nil)

	suite.mockDataStore.EXPECT().
		FetchNodeResolverMapEntry(gomock.Any(), &datastore.FetchNodeResolverMapEntryRequest{
			BaseSpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.FetchNodeResolverMapEntryResponse{
			NodeResolverMapEntryList: data.nodeResolutionList,
		}, nil)

	suite.mockDataStore.EXPECT().
		ListMatchingEntries(gomock.Any(), &datastore.ListSelectorEntriesRequest{
			Selectors: []*common.Selector{data.selector},
		}).
		Return(&datastore.ListSelectorEntriesResponse{
			RegisteredEntryList: data.bySelectorsEntries,
		}, nil)

	for _, entry := range data.byParentIDEntries {
		suite.mockDataStore.EXPECT().
			ListParentIDEntries(gomock.Any(), &datastore.ListParentIDEntriesRequest{
				ParentId: entry.SpiffeId}).
			Return(&datastore.ListParentIDEntriesResponse{}, nil)
		suite.mockDataStore.EXPECT().
			FetchNodeResolverMapEntry(gomock.Any(), &datastore.FetchNodeResolverMapEntryRequest{
				BaseSpiffeId: entry.SpiffeId,
			}).
			Return(&datastore.FetchNodeResolverMapEntryResponse{}, nil)
	}

	// end FetchRegistrationEntries(baseSpiffeID)

	suite.mockDataStore.EXPECT().
		FetchBundle(gomock.Any(), &datastore.Bundle{
			TrustDomain: testTrustDomain.String()}).
		Return(&datastore.Bundle{
			TrustDomain: testTrustDomain.String(),
			CaCerts:     caCert.Raw}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(gomock.Any(), &ca.SignCsrRequest{
			Csr: data.request.Csrs[0], Ttl: data.byParentIDEntries[2].Ttl,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[0]}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(gomock.Any(), &ca.SignCsrRequest{
			Csr: data.request.Csrs[1], Ttl: data.byParentIDEntries[0].Ttl,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[1]}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(gomock.Any(), &ca.SignCsrRequest{
			Csr: data.request.Csrs[2], Ttl: data.byParentIDEntries[1].Ttl,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[2]}, nil)

	suite.server.EXPECT().Send(&node.FetchX509SVIDResponse{
		SvidUpdate: data.expectation,
	}).
		Return(nil)

	suite.server.EXPECT().Recv().Return(nil, io.EOF)

}

func getExpectedFetchX509SVID(data *fetchSVIDData) *node.SvidUpdate {
	//TODO: improve this, put it in an array in data and iterate it
	svids := map[string]*node.Svid{
		data.nodeSpiffeID:     {SvidCert: data.generatedCerts[0], Ttl: 4444},
		data.databaseSpiffeID: {SvidCert: data.generatedCerts[1], Ttl: 2222},
		data.blogSpiffeID:     {SvidCert: data.generatedCerts[2], Ttl: 3333},
	}

	// returned in sorted order (according to sorting rules in util.SortRegistrationEntries)
	registrationEntries := []*common.RegistrationEntry{
		data.byParentIDEntries[1],
		data.byParentIDEntries[0],
		data.bySelectorsEntries[0],
		data.byParentIDEntries[2],
	}

	caCert, _, _ := util.LoadCAFixture()
	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		Bundle:              caCert.Raw,
		RegistrationEntries: registrationEntries,
	}

	return svidUpdate
}

func getFakePeer() *peer.Peer {
	baseCert := getBytesFromPem("base_cert.pem")
	parsedCert, _ := x509.ParseCertificate(baseCert)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parsedCert},
	}

	fakePeer := &peer.Peer{
		Addr:     nil,
		AuthInfo: credentials.TLSInfo{State: state},
	}

	return fakePeer
}
