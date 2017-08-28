package node

import (
	"testing"

	"github.com/spiffe/sri/services"
	"github.com/stretchr/testify/suite"
)

type NodeServiceTestSuite struct {
	suite.Suite
	nodeService NodeService
}

func (suite *NodeServiceTestSuite) SetupTest() {
	attestationMock := &services.AttestationMock{}
	identityMock := &services.IdentityMock{}
	caMock := &services.CAMock{}
	suite.nodeService = NewService(attestationMock, identityMock, caMock)
}

func Test_FetchBaseSVID(t *testing.T) {

}
