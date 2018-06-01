package server

import (
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/upstreamca"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	t       *testing.T
	server  *Server
	catalog *mock_catalog.MockCatalog
	ca      *mock_ca.MockServerCa
	upsCa   *mock_upstreamca.MockUpstreamCa
}

func (suite *ServerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()

	suite.catalog = mock_catalog.NewMockCatalog(mockCtrl)
	suite.ca = mock_ca.NewMockServerCa(mockCtrl)
	suite.upsCa = mock_upstreamca.NewMockUpstreamCa(mockCtrl)

	logger, err := log.NewLogger("DEBUG", "")
	suite.Nil(err)
	suite.server = New(Config{
		Log: logger,
		TrustDomain: url.URL{
			Scheme: "spiffe",
			Host:   "example.org",
		},
	})
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) TestUmask() {
	suite.server.config.Umask = 0000
	suite.server.prepareUmask()
	f, err := ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err := os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0600), fi.Mode().Perm()) //0600 is permission set by TempFile()

	suite.server.config.Umask = 0777
	suite.server.prepareUmask()
	f, err = ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err = os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0000), fi.Mode().Perm())
}
