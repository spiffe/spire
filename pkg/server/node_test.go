package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"github.com/spiffe/spire/test/mock/common/context"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
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
	logHook          *test.Hook
	mockCatalog      *mock_catalog.MockCatalog
	mockDataStore    *mock_datastore.MockDataStore
	mockServerCA     *mock_ca.MockControlPlaneCa
	mockNodeAttestor *mock_nodeattestor.MockNodeAttestor
	mockNodeResolver *mock_noderesolver.MockNodeResolver
	mockContext      *mock_context.MockContext
}

func SetupNodeTest(t *testing.T) *NodeServerTestSuite {
	suite := &NodeServerTestSuite{}
	mockCtrl := gomock.NewController(t)
	suite.ctrl = mockCtrl
	log, logHook := test.NewNullLogger()
	suite.logHook = logHook
	suite.mockCatalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.mockDataStore = mock_datastore.NewMockDataStore(mockCtrl)
	suite.mockServerCA = mock_ca.NewMockControlPlaneCa(mockCtrl)
	suite.mockNodeAttestor = mock_nodeattestor.NewMockNodeAttestor(mockCtrl)
	suite.mockNodeResolver = mock_noderesolver.NewMockNodeResolver(mockCtrl)
	suite.mockContext = mock_context.NewMockContext(mockCtrl)

	suite.nodeServer = &nodeServer{
		l:               log,
		catalog:         suite.mockCatalog,
		baseSpiffeIDTTL: 777,
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

	if !reflect.DeepEqual(response.SvidUpdate, expected) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response.SvidUpdate, expected)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}
}

func TestFetchSVID(t *testing.T) {
	suite := SetupNodeTest(t)
	defer suite.ctrl.Finish()

	data := getFetchSVIDTestData()
	setFetchSVIDExpectations(suite, data)
	response, err := suite.nodeServer.FetchSVID(suite.mockContext, data.request)
	expected := getExpectedFetchSVID(data)

	if !reflect.DeepEqual(response.SvidUpdate, expected) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response.SvidUpdate, expected)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

}

func getBytesFromPem(fileName string) []byte {
	pemFile, _ := ioutil.ReadFile(path.Join("_test_data", fileName))
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
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "bar"},
				&common.Selector{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test1"},
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "bar"},
				&common.Selector{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"}}

	data.regEntrySelectorList = []*common.RegistrationEntry{
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "car"},
				&common.Selector{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"},
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "bar"},
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
				CertExpirationDate: "Sun, 03 Oct 2027 20:21:55 +0000",
				CertSerialNumber:   "15130166154287189008",
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
		ListSelectorEntries(&datastore.ListSelectorEntriesRequest{
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
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "bar"},
				&common.Selector{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated",
		},
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test2",
		},
		&common.RegistrationEntry{
			Selectors: []*common.Selector{
				&common.Selector{Type: "foo", Value: "bar"},
				&common.Selector{Type: "foo", Value: "car"},
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
	nodeResolutionList []*datastore.NodeResolverMapEntry
	bySelectorsEntries []*common.RegistrationEntry
	byParentIDEntries  []*common.RegistrationEntry
}

func getFetchSVIDTestData() *fetchSVIDData {
	data := &fetchSVIDData{}
	data.baseSpiffeID = "spiffe://example.org/spire/agent/join_token/token"
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
		&datastore.NodeResolverMapEntry{
			BaseSpiffeId: data.baseSpiffeID,
			Selector:     data.selector,
		},
	}

	data.bySelectorsEntries = []*common.RegistrationEntry{
		&common.RegistrationEntry{SpiffeId: data.nodeSpiffeID, Ttl: 1111},
	}

	data.byParentIDEntries = []*common.RegistrationEntry{
		&common.RegistrationEntry{SpiffeId: data.databaseSpiffeID, Ttl: 2222},
		&common.RegistrationEntry{SpiffeId: data.blogSpiffeID, Ttl: 3333},
	}

	return data
}

func setFetchSVIDExpectations(
	suite *NodeServerTestSuite, data *fetchSVIDData) {

	suite.mockCatalog.EXPECT().DataStores().AnyTimes().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockCatalog.EXPECT().CAs().AnyTimes().
		Return([]ca.ControlPlaneCa{suite.mockServerCA})

	suite.mockContext.EXPECT().Value(gomock.Any()).Return(getFakePeer())

	suite.mockDataStore.EXPECT().FetchNodeResolverMapEntry(
		&datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: data.baseSpiffeID}).
		Return(&datastore.FetchNodeResolverMapEntryResponse{
			NodeResolverMapEntryList: data.nodeResolutionList}, nil)

	suite.mockDataStore.EXPECT().
		ListSelectorEntries(&datastore.ListSelectorEntriesRequest{
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
			Csr: data.request.Csrs[0], Ttl: data.bySelectorsEntries[0].Ttl,
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

}

func getExpectedFetchSVID(data *fetchSVIDData) *node.SvidUpdate {
	svids := map[string]*node.Svid{
		data.nodeSpiffeID:     &node.Svid{SvidCert: data.generatedCerts[0], Ttl: 1111},
		data.databaseSpiffeID: &node.Svid{SvidCert: data.generatedCerts[1], Ttl: 2222},
		data.blogSpiffeID:     &node.Svid{SvidCert: data.generatedCerts[2], Ttl: 3333},
	}

	registrationEntries := []*common.RegistrationEntry{
		data.bySelectorsEntries[0],
		data.byParentIDEntries[0],
		data.byParentIDEntries[1],
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
