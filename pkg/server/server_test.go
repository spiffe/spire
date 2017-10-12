package server

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	t      *testing.T
	server Server
}

func (suite *ServerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()

	logger, err := log.NewLogger("DEBUG", "")
	suite.Nil(err)
	suite.server = Server{
		Config: &Config{
			Log: logger,
		},
	}
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) TestUmask() {
	suite.server.Config.Umask = 0000
	suite.server.prepareUmask()
	f, err := ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err := os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0600), fi.Mode().Perm()) //0600 is permission set by TempFile()

	suite.server.Config.Umask = 0777
	suite.server.prepareUmask()
	f, err = ioutil.TempFile("", "")
	suite.Nil(err)
	defer os.Remove(f.Name())
	fi, err = os.Stat(f.Name())
	suite.Nil(err)
	suite.Equal(os.FileMode(0000), fi.Mode().Perm())
}
