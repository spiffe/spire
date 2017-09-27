package server

import (
	"testing"

	//"github.com/golang/mock/gomock"
	//pb "github.com/spiffe/spire/pkg/api/node"
	//"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	//"github.com/spiffe/spire/pkg/server/nodeattestor"

	"github.com/stretchr/testify/suite"
)

type NodeServiceTestSuite struct {
	suite.Suite
	t             *testing.T
	server        nodeServer
	mockServerCA  *ca.MockControlPlaneCa
	mockDataStore *datastore.MockDataStore
}

/*
func (suite *NodeServiceTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()

	suite.mockCA = services.NewMockCA(mockCtrl)
	suite.mockIdentity = services.NewMockIdentity(mockCtrl)
	suite.mockAttestation = services.NewMockAttestation(mockCtrl)

	suite.mockServerCA = ca.NewMockControlPlaneCa(mockCtrl)
	suite.mockDataStore = datastore.NewMockDataStore(mockCtrl)

	suite.nodeService = NewService(Config{
		Attestation:     suite.mockAttestation,
		CA:              suite.mockCA,
		Identity:        suite.mockIdentity,
		ServerCA:        suite.mockServerCA,
		DataStore:       suite.mockDataStore,
		BaseSpiffeIDTTL: 7777,
	})
}

func TestNodeServiceTestSuite(t *testing.T) {
	suite.Run(t, new(NodeServiceTestSuite))
}

func (suite *NodeServiceTestSuite) TestFetchBaseSVID() {
	type SelectorList []*common.Selector
	type RegEntryList []*common.RegistrationEntry

	fakeCsr := &ca.SignCsrRequest{Csr: []byte("fake csr")}
	fakeCert := &ca.SignCsrResponse{SignedCertificate: []byte("fake cert")}
	attestData := &common.AttestedData{Type: "", Data: []byte("fake attestation data")}
	baseSpiffeID := "spiffe://trust-domain/path"
	selector := &common.Selector{Type: "foo", Value: "bar"}
	selectors := make(map[string]*common.Selectors)
	selectors[baseSpiffeID] = &common.Selectors{Entries: []*common.Selector{selector}}
	regEntryParentIDList := RegEntryList{&common.RegistrationEntry{
		Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}, &common.Selector{Type: "foo", Value: "car"}},
		ParentId:  "spiffe://trust-domain/path",
		SpiffeId:  "spiffe:test1"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}, &common.Selector{Type: "foo", Value: "car"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:repeated"}}
	regEntrySelectorList := RegEntryList{&common.RegistrationEntry{
		Selectors: SelectorList{&common.Selector{Type: "foo", Value: "car"}, &common.Selector{Type: "foo", Value: "bar"}},
		ParentId:  "spiffe://trust-domain/path",
		SpiffeId:  "spiffe:repeated"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:test2"}}

	expectedRegEntries := RegEntryList{&common.RegistrationEntry{
		Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}, &common.Selector{Type: "foo", Value: "car"}},
		ParentId:  "spiffe://trust-domain/path",
		SpiffeId:  "spiffe:repeated"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:test2"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}, &common.Selector{Type: "foo", Value: "car"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:test1"}}

	//happy path
	suite.mockCA.EXPECT().GetSpiffeIDFromCSR([]byte("fake csr")).Return(baseSpiffeID, nil)
	suite.mockAttestation.EXPECT().IsAttested(baseSpiffeID).Return(false, nil)
	suite.mockAttestation.EXPECT().Attest(attestData, false).Return(&nodeattestor.AttestResponse{BaseSPIFFEID: baseSpiffeID, Valid: true}, nil)
	suite.mockCA.EXPECT().SignCsr(fakeCsr).Return(fakeCert, nil)
	suite.mockAttestation.EXPECT().CreateEntry(attestData.Type, baseSpiffeID, fakeCert.SignedCertificate).Return(nil)
	suite.mockIdentity.EXPECT().Resolve([]string{baseSpiffeID}).Return(selectors, nil)
	suite.mockIdentity.EXPECT().CreateEntry(baseSpiffeID, selectors[baseSpiffeID].Entries[0]).Return(nil)
	suite.mockDataStore.EXPECT().
		ListSelectorEntries(&datastore.ListSelectorEntriesRequest{Selector: selector}).
		Return(&datastore.ListSelectorEntriesResponse{RegisteredEntryList: regEntrySelectorList}, nil)
	suite.mockDataStore.EXPECT().
		ListParentIDEntries(&datastore.ListParentIDEntriesRequest{ParentId: baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{RegisteredEntryList: regEntryParentIDList}, nil)

	response, err := suite.nodeService.FetchBaseSVID(nil, node.FetchBaseSVIDRequest{
		AttestedData: attestData,
		Csr:          fakeCsr.Csr,
	})

	svids := make(map[string]*node.Svid)
	svids[baseSpiffeID] = &node.Svid{SvidCert: fakeCert.SignedCertificate, Ttl: 7777}

	svidUpdate := &node.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: expectedRegEntries,
	}

	suite.Assertions.EqualValues(response.SvidUpdate, svidUpdate)
	suite.Assertions.Nil(err, "There should be no error.")
}

func (suite *NodeServiceTestSuite) TestFetchSVID() {
	const baseSpiffeID = "spiffe://example.org/spiffe/node-id/token"
	const nodeSpiffeID = "spiffe://example.org/spiffe/node-id/tokenfoo"
	const databaseSpiffeID = "spiffe://example.org/database"
	const blogSpiffeID = "spiffe://example.org/blog"

	fakeCsrs := [][]byte{
		[]byte("node csr"),
		[]byte("database csr"),
		[]byte("blog csr"),
	}

	fakeCerts := [][]byte{
		[]byte("node cert"),
		[]byte("database cert"),
		[]byte("blog cert"),
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

	suite.mockDataStore.EXPECT().
		FetchNodeResolverMapEntry(&datastore.FetchNodeResolverMapEntryRequest{BaseSpiffeId: baseSpiffeID}).
		Return(&datastore.FetchNodeResolverMapEntryResponse{
			NodeResolverMapEntryList: nodeResolutionList}, nil)

	suite.mockDataStore.EXPECT().
		ListSelectorEntries(&datastore.ListSelectorEntriesRequest{Selector: selector}).
		Return(&datastore.ListSelectorEntriesResponse{RegisteredEntryList: bySelectorsEntries}, nil)

	suite.mockDataStore.EXPECT().
		ListParentIDEntries(&datastore.ListParentIDEntriesRequest{ParentId: baseSpiffeID}).
		Return(&datastore.ListParentIDEntriesResponse{RegisteredEntryList: byParentIDEntries}, nil)

	suite.mockCA.EXPECT().
		GetSpiffeIDFromCSR(fakeCsrs[0]).
		Return(nodeSpiffeID, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{Csr: fakeCsrs[0]}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCerts[0]}, nil)

	suite.mockCA.EXPECT().
		GetSpiffeIDFromCSR(fakeCsrs[1]).
		Return(databaseSpiffeID, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{Csr: fakeCsrs[1]}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCerts[1]}, nil)

	suite.mockCA.EXPECT().
		GetSpiffeIDFromCSR(fakeCsrs[2]).
		Return(blogSpiffeID, nil)

	suite.mockServerCA.EXPECT().
		SignCsr(&ca.SignCsrRequest{Csr: fakeCsrs[2]}).
		Return(&ca.SignCsrResponse{SignedCertificate: fakeCerts[2]}, nil)

	response, err := suite.nodeService.FetchSVID(nil, node.FetchSVIDRequest{
		Csrs: fakeCsrs,
	})

	expectedResponse := &node.SvidUpdate{
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

	suite.Assertions.Equal(expectedResponse, response.SvidUpdate)
	suite.Assertions.Nil(err, "There should be no error.")
}
*/
