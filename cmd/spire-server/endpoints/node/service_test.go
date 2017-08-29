package node

import (
	"testing"

	"github.com/spiffe/sri/services"

	"github.com/golang/mock/gomock"
	pb "github.com/spiffe/sri/pkg/api/node"
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
	"github.com/stretchr/testify/suite"
)

type NodeServiceTestSuite struct {
	suite.Suite
	t               *testing.T
	nodeService     NodeService
	mockCA          *services.MockCA
	mockIdentity    *services.MockIdentity
	mockAttestation *services.MockAttestation
}

func (suite *NodeServiceTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()

	suite.mockCA = services.NewMockCA(mockCtrl)
	suite.mockIdentity = services.NewMockIdentity(mockCtrl)
	suite.mockAttestation = services.NewMockAttestation(mockCtrl)

	suite.nodeService = NewService(ServiceConfig{
		Attestation: suite.mockAttestation,
		CA:          suite.mockCA,
		Identity:    suite.mockIdentity,
	})
}

func TestNodeServiceTestSuite(t *testing.T) {
	suite.Run(t, new(NodeServiceTestSuite))
}

func (suite *NodeServiceTestSuite) TestFetchBaseSVID() {
	fakeCsr := []byte("fake csr")
	fakeCert := []byte("fake cert")
	attestData := &common.AttestedData{Type: "", Data: []byte("fake attestation data")}
	baseSpiffeID := "spiffe://trust-domain/path"
	selector := &common.Selector{Type: "foo", Value: "bar"}
	selectors := make(map[string]*common.Selectors)
	selectors[baseSpiffeID] = &common.Selectors{Entries: []*common.Selector{selector}}

	//happy path
	suite.mockCA.EXPECT().GetSpiffeIDFromCSR([]byte("fake csr")).Return(baseSpiffeID, nil)
	suite.mockAttestation.EXPECT().IsAttested(baseSpiffeID).Return(false, nil)
	suite.mockAttestation.EXPECT().Attest(attestData, false).Return(&nodeattestor.AttestResponse{BaseSPIFFEID: baseSpiffeID, Valid: true}, nil)
	suite.mockCA.EXPECT().SignCsr(fakeCsr).Return(fakeCert, nil)
	suite.mockAttestation.EXPECT().CreateEntry(attestData.Type, baseSpiffeID, fakeCert).Return(nil)
	suite.mockIdentity.EXPECT().Resolve([]string{baseSpiffeID}).Return(selectors, nil)
	suite.mockIdentity.EXPECT().CreateEntry(baseSpiffeID, selectors[baseSpiffeID].Entries[0]).Return(nil)

	response, err := suite.nodeService.FetchBaseSVID(nil, pb.FetchBaseSVIDRequest{
		AttestedData: attestData,
		Csr:          fakeCsr,
	})

	svids := make(map[string]*pb.Svid)
	svids[baseSpiffeID] = &pb.Svid{SvidCert: fakeCert, Ttl: 999}
	registrationEntry := &common.RegistrationEntry{
		SpiffeId:  baseSpiffeID,
		Selectors: selectors[baseSpiffeID].Entries,
	}
	svidUpdate := &pb.SvidUpdate{
		Svids: svids,
		RegistrationEntryList: []*common.RegistrationEntry{registrationEntry},
	}

	suite.Assertions.Equal(response.SpiffeEntry, svidUpdate)
	suite.Assertions.Nil(err, "There should be no error.")
}
