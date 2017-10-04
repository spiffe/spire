package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

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
}

func SetupTest(t *testing.T) *NodeServerTestSuite {
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

	suite.nodeServer = &nodeServer{
		l:               log,
		catalog:         suite.mockCatalog,
		baseSpiffeIDTTL: 7777,
		fromContext:     fakeFromContext,
	}
	return suite
}

func TestFetchBaseSVID(t *testing.T) {
	suite := SetupTest(t)
	defer suite.ctrl.Finish()

	type SelectorList []*common.Selector
	type RegEntryList []*common.RegistrationEntry

	fakeCsr := getBytesFromPem("base_csr.pem")
	fakeCert := getBytesFromPem("base_cert.pem")

	attestData := &common.AttestedData{
		Type: "fake type",
		Data: []byte("fake attestation data"),
	}
	const baseSpiffeID = "spiffe://example.org/spiffe/node-id/token"
	selector := &common.Selector{Type: "foo", Value: "bar"}
	selectors := make(map[string]*common.Selectors)
	selectors[baseSpiffeID] = &common.Selectors{Entries: []*common.Selector{selector}}

	regEntryParentIDList := RegEntryList{
		&common.RegistrationEntry{
			Selectors: SelectorList{
				&common.Selector{Type: "foo", Value: "bar"},
				&common.Selector{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test1"},
		&common.RegistrationEntry{
			Selectors: SelectorList{
				&common.Selector{Type: "foo", Value: "bar"},
				&common.Selector{Type: "foo", Value: "car"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"}}

	regEntrySelectorList := RegEntryList{
		&common.RegistrationEntry{
			Selectors: SelectorList{
				&common.Selector{Type: "foo", Value: "car"},
				&common.Selector{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://repeated"},
		&common.RegistrationEntry{
			Selectors: SelectorList{
				&common.Selector{Type: "foo", Value: "bar"},
			},
			ParentId: "spiffe://example.org/path",
			SpiffeId: "spiffe://test2",
		},
	}

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
			BaseSpiffeId: baseSpiffeID,
		}).
		Return(&datastore.FetchAttestedNodeEntryResponse{AttestedNodeEntry: nil}, nil)

	suite.mockNodeAttestor.EXPECT().Attest(&nodeattestor.AttestRequest{
		AttestedBefore: false,
		AttestedData:   attestData,
	}).
		Return(&nodeattestor.AttestResponse{BaseSPIFFEID: baseSpiffeID, Valid: true}, nil)

	suite.mockServerCA.EXPECT().SignCsr(&ca.SignCsrRequest{Csr: fakeCsr}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCert}, nil)

	suite.mockDataStore.EXPECT().CreateAttestedNodeEntry(
		&datastore.CreateAttestedNodeEntryRequest{
			AttestedNodeEntry: &datastore.AttestedNodeEntry{
				AttestedDataType:   "fake type",
				BaseSpiffeId:       baseSpiffeID,
				CertExpirationDate: "Sat, 02 Oct 2027 16:18:38 +0000",
				CertSerialNumber:   "16484605349331937401",
			}}).
		Return(nil, nil)

	suite.mockNodeResolver.EXPECT().Resolve([]string{baseSpiffeID}).
		Return(selectors, nil)
	suite.mockDataStore.EXPECT().CreateNodeResolverMapEntry(
		&datastore.CreateNodeResolverMapEntryRequest{
			NodeResolverMapEntry: &datastore.NodeResolverMapEntry{
				BaseSpiffeId: baseSpiffeID,
				Selector:     selector,
			},
		}).
		Return(nil, nil)

	suite.mockDataStore.EXPECT().
		ListSelectorEntries(&datastore.ListSelectorEntriesRequest{
			Selectors: []*common.Selector{selector},
		}).
		Return(&datastore.ListSelectorEntriesResponse{
			RegisteredEntryList: regEntrySelectorList,
		}, nil)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(
			&datastore.ListParentIDEntriesRequest{ParentId: baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{
			RegisteredEntryList: regEntryParentIDList}, nil)

	response, err := suite.nodeServer.FetchBaseSVID(nil, &node.FetchBaseSVIDRequest{
		AttestedData: attestData,
		Csr:          fakeCsr,
	})

	expected := getExpectedFetchBaseSVID(baseSpiffeID, fakeCert)

	if !reflect.DeepEqual(response.SvidUpdate, expected) {
		t.Errorf("Response was incorrect\n Got: %v\n Want: %v\n",
			response.SvidUpdate, expected)
	}

	if err != nil {
		t.Errorf("Error was not expected\n Got: %v\n Want: %v\n", err, nil)
	}

}

func TestFetchSVID(t *testing.T) {
	suite := SetupTest(t)
	defer suite.ctrl.Finish()

	const baseSpiffeID = "spiffe://example.org/spire/agent/join_token/token"
	const nodeSpiffeID = "spiffe://example.org/spire/agent/join_token/tokenfoo"
	const databaseSpiffeID = "spiffe://example.org/database"
	const blogSpiffeID = "spiffe://example.org/blog"

	fakeCsrs := [][]byte{
		getBytesFromPem("node_csr.pem"),
		getBytesFromPem("database_csr.pem"),
		getBytesFromPem("blog_csr.pem"),
	}

	fakeCerts := [][]byte{
		getBytesFromPem("node_cert.pem"),
		getBytesFromPem("database_cert.pem"),
		getBytesFromPem("blog_cert.pem"),
	}

	selector := &common.Selector{Type: "foo", Value: "bar"}
	nodeResolutionList := []*datastore.NodeResolverMapEntry{
		&datastore.NodeResolverMapEntry{
			BaseSpiffeId: baseSpiffeID,
			Selector:     selector,
		},
	}

	bySelectorsEntries := []*common.RegistrationEntry{
		&common.RegistrationEntry{SpiffeId: nodeSpiffeID, Ttl: 1111},
	}

	byParentIDEntries := []*common.RegistrationEntry{
		&common.RegistrationEntry{SpiffeId: databaseSpiffeID, Ttl: 2222},
		&common.RegistrationEntry{SpiffeId: blogSpiffeID, Ttl: 3333},
	}

	suite.mockCatalog.EXPECT().DataStores().AnyTimes().
		Return([]datastore.DataStore{suite.mockDataStore})
	suite.mockCatalog.EXPECT().CAs().AnyTimes().
		Return([]ca.ControlPlaneCa{suite.mockServerCA})

	suite.mockDataStore.EXPECT().
		FetchNodeResolverMapEntry(&datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}).
		Return(&datastore.FetchNodeResolverMapEntryResponse{
			NodeResolverMapEntryList: nodeResolutionList}, nil)

	suite.mockDataStore.EXPECT().
		ListSelectorEntries(&datastore.ListSelectorEntriesRequest{Selectors: []*common.Selector{selector}}).
		Return(&datastore.ListSelectorEntriesResponse{RegisteredEntryList: bySelectorsEntries}, nil)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(&datastore.ListParentIDEntriesRequest{ParentId: baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{RegisteredEntryList: byParentIDEntries}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{Csr: fakeCsrs[0]}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCerts[0]}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{Csr: fakeCsrs[1]}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCerts[1]}, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{Csr: fakeCsrs[2]}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCerts[2]}, nil)

	response, err := suite.nodeServer.FetchSVID(nil, &node.FetchSVIDRequest{
		Csrs: fakeCsrs,
	})

	expected := &node.SvidUpdate{
		Svids: map[string]*node.Svid{
			nodeSpiffeID:     &node.Svid{SvidCert: fakeCerts[0], Ttl: 1111},
			databaseSpiffeID: &node.Svid{SvidCert: fakeCerts[1], Ttl: 2222},
			blogSpiffeID:     &node.Svid{SvidCert: fakeCerts[2], Ttl: 3333},
		},
		RegistrationEntries: []*common.RegistrationEntry{
			bySelectorsEntries[0],
			byParentIDEntries[0],
			byParentIDEntries[1],
		},
	}

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
	svids[baseSpiffeID] = &node.Svid{SvidCert: cert, Ttl: 7777}

	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: expectedRegEntries,
	}

	return svidUpdate
}

func fakeFromContext(ctx context.Context) (*peer.Peer, bool) {
	baseCert := getBytesFromPem("base_cert.pem")
	parsedCert, _ := x509.ParseCertificate(baseCert)

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parsedCert},
	}

	fakePeer := &peer.Peer{
		Addr:     nil,
		AuthInfo: credentials.TLSInfo{State: state},
	}
	return fakePeer, true
}
