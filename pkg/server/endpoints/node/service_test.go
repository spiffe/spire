package node

import (
	"testing"

	"github.com/spiffe/spire/services"

	"github.com/golang/mock/gomock"
	pb "github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/nodeattestor"
	"github.com/stretchr/testify/suite"
)

type NodeServiceTestSuite struct {
	suite.Suite
	t                *testing.T
	nodeService      NodeService
	mockCA           *services.MockCA
	mockIdentity     *services.MockIdentity
	mockAttestation  *services.MockAttestation
	mockRegistration *services.MockRegistration
}

func (suite *NodeServiceTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()

	suite.mockCA = services.NewMockCA(mockCtrl)
	suite.mockIdentity = services.NewMockIdentity(mockCtrl)
	suite.mockAttestation = services.NewMockAttestation(mockCtrl)
	suite.mockRegistration = services.NewMockRegistration(mockCtrl)

	suite.nodeService = NewService(ServiceConfig{
		Attestation:     suite.mockAttestation,
		CA:              suite.mockCA,
		Identity:        suite.mockIdentity,
		Registration:    suite.mockRegistration,
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
		Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"},&common.Selector{Type: "foo", Value: "car"}},
		ParentId:  "spiffe://trust-domain/path",
		SpiffeId:  "spiffe:test1"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"},&common.Selector{Type: "foo", Value: "car"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:repeated"}}
	regEntrySelectorList := RegEntryList{&common.RegistrationEntry{
		Selectors: SelectorList{&common.Selector{Type: "foo", Value: "car"},&common.Selector{Type: "foo", Value: "bar"}},
		ParentId:  "spiffe://trust-domain/path",
		SpiffeId:  "spiffe:repeated"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:test2"}}

	expectedRegEntries := RegEntryList{&common.RegistrationEntry{
		Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"},&common.Selector{Type: "foo", Value: "car"}},
		ParentId:  "spiffe://trust-domain/path",
		SpiffeId:  "spiffe:repeated"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"}},
			ParentId:  "spiffe://trust-domain/path",
			SpiffeId:  "spiffe:test2"},
		&common.RegistrationEntry{
			Selectors: SelectorList{&common.Selector{Type: "foo", Value: "bar"},&common.Selector{Type: "foo", Value: "car"}},
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
	suite.mockRegistration.EXPECT().ListEntryByParentSpiffeID(baseSpiffeID).Return(regEntryParentIDList, nil)
	suite.mockRegistration.EXPECT().ListEntryBySelector(&common.Selector{Type: "foo", Value: "bar"}).Return(regEntrySelectorList, nil)

	response, err := suite.nodeService.FetchBaseSVID(nil, pb.FetchBaseSVIDRequest{
		AttestedData: attestData,
		Csr:          fakeCsr.Csr,
	})

	svids := make(map[string]*pb.Svid)
	svids[baseSpiffeID] = &pb.Svid{SvidCert: fakeCert.SignedCertificate, Ttl: 7777}

	svidUpdate := &pb.SvidUpdate{
		Svids:               svids,
		RegistrationEntries: expectedRegEntries,
	}

	suite.Assertions.EqualValues(response.SvidUpdate, svidUpdate)
	suite.Assertions.Nil(err, "There should be no error.")
}
