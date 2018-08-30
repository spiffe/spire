package server

import (
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/test/mock/proto/server/upstreamca"
	"github.com/spiffe/spire/test/mock/server/catalog"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	server  *Server
	catalog *mock_catalog.MockCatalog
	upsCa   *mock_upstreamca.MockUpstreamCA

	mockCtrl *gomock.Controller
}

func (suite *ServerTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())

	suite.catalog = mock_catalog.NewMockCatalog(suite.mockCtrl)
	suite.upsCa = mock_upstreamca.NewMockUpstreamCA(suite.mockCtrl)

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

func (s *ServerTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
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
