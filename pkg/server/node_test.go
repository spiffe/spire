package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/url"
	"path"
	"reflect"
	"testing"

	"github.com/spiffe/spire/test/mock/common/context"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/server/noderesolver"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/stretchr/testify/suite"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type NodeServerTestSuite struct {
	suite.Suite
	t                *testing.T
	ctrl             *gomock.Controller
	nodeServer       *nodeServer
	mockCatalog      *mock_catalog.MockCatalog
	mockDataStore    *mock_datastore.MockDataStore
	mockServerCA     *mock_ca.MockControlPlaneCa
	mockNodeAttestor *mock_nodeattestor.MockNodeAttestor
	mockNodeResolver *mock_noderesolver.MockNodeResolver
	mockContext      *mock_context.MockContext
	server           *mock_node.MockNode_FetchSVIDServer
}

func SetupNodeTest(t *testing.T) *NodeServerTestSuite {
	suite := &NodeServerTestSuite{}
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, _ := test.NewNullLogger()
	suite.mockCatalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)
	suite.mockServerCA = mock_ca.NewMockControlPlaneCa(mockCtrl)
	suite.mockNodeAttestor = mock_nodeattestor.NewMockNodeAttestor(mockCtrl)
	suite.mockNodeResolver = mock_noderesolver.NewMockNodeResolver(mockCtrl)
	suite.mockContext = mock_context.NewMockContext(mockCtrl)
	suite.server = mock_node.NewMockNode_FetchSVIDServer(suite.ctrl)

	trustDomain := url.URL{
		Scheme: "spiffe",
		Host:   "example.org",
	}

	suite.nodeServer = &nodeServer{
		l:           log,
		catalog:     suite.mockCatalog,
		baseSVIDTtl: 777,
		trustDomain: trustDomain,
	}
	return suite
}

func TestFetchBaseSVID(t *testing.T) {
	suite := SetupNodeTest(t)
	defer suite.ctrl.Finish()

	data := getFetchBaseSVIDTestData()
	setFetchBaseSVIDExpectations(suite, data)
	response, err := suite.nodeServer.FetchBaseSVID(nil, data.request)
	expected := getExpectedFetchBaseSVID(data.baseSpiffeID, data.generatedCert)

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

	if !reflect.DeepEqual(response.SvidUpdate, expected) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response.SvidUpdate, expected)
	}
}

func TestFetchSVID(t *testing.T) {
	suite := SetupNodeTest(t)
	defer suite.ctrl.Finish()

	data := getFetchSVIDTestData()
	data.expectation = getExpectedFetchSVID(data)
	setFetchSVIDExpectations(suite, data)

	err := suite.nodeServer.FetchSVID(suite.server)
	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

}

func TestFetchSVIDWithRotation(t *testing.T) {
	suite := SetupNodeTest(t)
	defer suite.ctrl.Finish()

	data := getFetchSVIDTestData()
	data.request.Csrs = append(
		data.request.Csrs, getBytesFromPem("base_rotated_csr.pem"))
	data.generatedCerts = append(
		data.generatedCerts, getBytesFromPem("base_rotated_cert.pem"))

	data.expectation = getExpectedFetchSVID(data)
	data.expectation.Svids[data.baseSpiffeID] = &node.Svid{SvidCert: data.generatedCerts[3], Ttl: 777}
	setFetchSVIDExpectations(suite, data)

	suite.mockDataStore.EXPECT().FetchAttestedNodeEntry(
		&datastore.FetchAttestedNodeEntryRequest{BaseSpiffeId: data.baseSpiffeID},
	).
		Return(&datastore.FetchAttestedNodeEntryResponse{
			AttestedNodeEntry: &datastore.AttestedNodeEntry{
				CertSerialNumber: "18392437442709699290",
			},
		}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{
			Csr: data.request.Csrs[3], Ttl: 777,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[3]}, nil)

	suite.mockDataStore.EXPECT().
		UpdateAttestedNodeEntry(gomock.Any()).
		Return(&datastore.UpdateAttestedNodeEntryResponse{}, nil)

	err := suite.nodeServer.FetchSVID(suite.server)

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

}

func getBytesFromPem(fileName string) []byte {
	pemFile, _ := ioutil.ReadFile(path.Join("../../test/fixture/certs", fileName))
	decodedFile, _ := pem.Decode(pemFile)
	return decodedFile.Bytes
}

type fetchBaseSVIDData struct {
	request              *node.FetchBaseSVIDRequest
	generatedCert        []byte
	baseSpiffeID         string
	selector             *common.Selector
	selectors            map[string]*common.Selectors
	regEntryParentIDList []*common.RegistrationEntry
	regEntrySelectorList []*common.RegistrationEntry
}

func getFetchBaseSVIDTestData() *fetchBaseSVIDData {
	data := &fetchBaseSVIDData{}

	data.request = &node.FetchBaseSVIDRequest{
		Csr: getBytesFromPem("base_csr.pem"),
		AttestedData: &common.AttestedData{
			Type: "fake type",
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
				{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test1"},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
				{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"}}

	data.regEntrySelectorList = []*common.RegistrationEntry{
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "car"},
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

func setFetchBaseSVIDExpectations(
	suite *NodeServerTestSuite, data *fetchBaseSVIDData) {

	suite.mockCatalog.EXPECT().DataStores().AnyTimes().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockCatalog.EXPECT().CAs().AnyTimes().
		Return([]ca.ControlPlaneCa{suite.mockServerCA})
	suite.mockCatalog.EXPECT().NodeAttestors().AnyTimes().
		Return([]nodeattestor.NodeAttestor{suite.mockNodeAttestor})
	suite.mockCatalog.EXPECT().NodeResolvers().AnyTimes().
		Return([]noderesolver.NodeResolver{suite.mockNodeResolver})

	p := &catalog.ManagedPlugin{
		Plugin: suite.mockNodeAttestor,
		Config: catalog.PluginConfig{
			PluginName: "fake type",
		},
	}
	suite.mockCatalog.EXPECT().Find(suite.mockNodeAttestor).Return(p)

	suite.mockDataStore.EXPECT().FetchAttestedNodeEntry(
		&datastore.FetchAttestedNodeEntryRequest{
			BaseSpiffeId: data.baseSpiffeID,
		}).
		Return(&datastore.FetchAttestedNodeEntryResponse{AttestedNodeEntry: nil}, nil)

	suite.mockNodeAttestor.EXPECT().Attest(&nodeattestor.AttestRequest{
		AttestedBefore: false,
		AttestedData:   data.request.AttestedData,
	}).
		Return(&nodeattestor.AttestResponse{
			BaseSPIFFEID: data.baseSpiffeID,
			Valid:        true}, nil)

	suite.mockServerCA.EXPECT().SignCsr(&ca.SignCsrRequest{
		Csr: data.request.Csr,
		Ttl: 777,
	}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCert}, nil)

	suite.mockDataStore.EXPECT().CreateAttestedNodeEntry(
		&datastore.CreateAttestedNodeEntryRequest{
			AttestedNodeEntry: &datastore.AttestedNodeEntry{
				AttestedDataType:   "fake type",
				BaseSpiffeId:       data.baseSpiffeID,
				CertExpirationDate: "Mon, 04 Oct 2027 21:19:54 +0000",
				CertSerialNumber:   "18392437442709699290",
			}}).
		Return(nil, nil)

	suite.mockNodeResolver.EXPECT().Resolve([]string{data.baseSpiffeID}).
		Return(data.selectors, nil)

	suite.mockDataStore.EXPECT().CreateNodeResolverMapEntry(
		&datastore.CreateNodeResolverMapEntryRequest{
			NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
				BaseSpiffeId: data.baseSpiffeID,
				Selector:     data.selector,
			},
		}).
		Return(nil, nil)

	suite.mockDataStore.EXPECT().
		ListMatchingEntries(&datastore.ListSelectorEntriesRequest{
			Selectors: []*common.Selector{data.selector},
		}).
		Return(&datastore.ListSelectorEntriesResponse{
			RegisteredEntryList: data.regEntrySelectorList,
		}, nil)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(
			&datastore.ListParentIDEntriesRequest{ParentId: data.baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{
			RegisteredEntryList: data.regEntryParentIDList}, nil)

}

func getExpectedFetchBaseSVID(baseSpiffeID string, cert []byte) *node.SvidUpdate {
	expectedRegEntries := []*common.RegistrationEntry{
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
				{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated",
		},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test2",
		},
		{
			Selectors: []*common.Selector{
				{Type: "foo", Value: "bar"},
				{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test1",
		},
	}

	svids := make(map[string]*node.Svid)
	svids[baseSpiffeID] = &node.Svid{SvidCert: cert, Ttl: 777}

	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: expectedRegEntries,
	}

	return svidUpdate
}

type fetchSVIDData struct {
	request            *node.FetchSVIDRequest
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

func getFetchSVIDTestData() *fetchSVIDData {
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

	data.request = &node.FetchSVIDRequest{}
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

func setFetchSVIDExpectations(
	suite *NodeServerTestSuite, data *fetchSVIDData) {

	suite.mockCatalog.EXPECT().DataStores().AnyTimes().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockCatalog.EXPECT().CAs().AnyTimes().
		Return([]ca.ControlPlaneCa{suite.mockServerCA})

	suite.server.EXPECT().Context().Return(suite.mockContext)
	suite.server.EXPECT().Recv().Return(data.request, nil)

	suite.mockContext.EXPECT().Value(gomock.Any()).Return(getFakePeer())

	suite.mockDataStore.EXPECT().FetchNodeResolverMapEntry(
		&datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: data.baseSpiffeID}).
		Return(&datastore.FetchNodeResolverMapEntryResponse{
			NodeResolverMapEntryList: data.nodeResolutionList}, nil)

	suite.mockDataStore.EXPECT().
		ListMatchingEntries(&datastore.ListSelectorEntriesRequest{
			Selectors: []*common.Selector{data.selector},
		}).
		Return(&datastore.ListSelectorEntriesResponse{
			RegisteredEntryList: data.bySelectorsEntries,
		}, nil)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(&datastore.ListParentIDEntriesRequest{
			ParentId: data.baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{
			RegisteredEntryList: data.byParentIDEntries}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{
			Csr: data.request.Csrs[0], Ttl: data.byParentIDEntries[2].Ttl,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[0]}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{
			Csr: data.request.Csrs[1], Ttl: data.byParentIDEntries[0].Ttl,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[1]}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{
			Csr: data.request.Csrs[2], Ttl: data.byParentIDEntries[1].Ttl,
		}).
		Return(&ca.SignCsrResponse{SignedCertificate: data.generatedCerts[2]}, nil)

	suite.server.EXPECT().Send(&node.FetchSVIDResponse{
		SvidUpdate: data.expectation,
	}).
		Return(nil)

	suite.server.EXPECT().Recv().Return(nil, io.EOF)

}

func getExpectedFetchSVID(data *fetchSVIDData) *node.SvidUpdate {
	//TODO: improve this, put it in an array in data and iterate it
	svids := map[string]*node.Svid{
		data.nodeSpiffeID:     {SvidCert: data.generatedCerts[0], Ttl: 4444},
		data.databaseSpiffeID: {SvidCert: data.generatedCerts[1], Ttl: 2222},
		data.blogSpiffeID:     {SvidCert: data.generatedCerts[2], Ttl: 3333},
	}

	registrationEntries := []*common.RegistrationEntry{
		data.bySelectorsEntries[0],
		data.byParentIDEntries[0],
		data.byParentIDEntries[1],
		data.byParentIDEntries[2],
	}

	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
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
