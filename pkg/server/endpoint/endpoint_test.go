package endpoint

import (
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestEndpoint(t *testing.T) {
	suite.Run(t, new(EndpointTestSuite))
}

type EndpointTestSuite struct {
	suite.Suite
	ctrl *gomock.Controller

	node         *mock_node.MockNodeServer
	registration *mock_registration.MockRegistrationServer

	e *endpoint
}

func (s *EndpointTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.node = mock_node.NewMockNodeServer(s.ctrl)
	s.registration = mock_registration.NewMockRegistrationServer(s.ctrl)

	log, _ := test.NewNullLogger()
	ip := net.ParseIP("127.0.0.1")
	svid, key, err := util.LoadSVIDFixture()
	require.NoError(s.T(), err)
	ca, _, err := util.LoadCAFixture()
	require.NoError(s.T(), err)

	c := &Config{
		NS:       s.node,
		RS:       s.registration,
		GRPCAddr: &net.TCPAddr{IP: ip, Port: 8000},
		HTTPAddr: &net.TCPAddr{IP: ip, Port: 8001},
		SVID:     svid,
		SVIDKey:  key,
		CACert:   ca,
		Log:      log,
	}
	s.e = New(c)
}

func (s *EndpointTestSuite) TestCreateGRPCServer() {
	s.e.createGRPCServer()
	s.Assert().NotNil(s.e.grpcServer)
}

func (s *EndpointTestSuite) TestCreateHTTPServer() {
	s.e.createHTTPServer()
	s.Assert().NotNil(s.e.httpServer)
}

func (s *EndpointTestSuite) TestInitRegistrationAPI() {
	s.e.createGRPCServer()
	s.e.createHTTPServer()

	err := s.e.initRegistrationAPI()
	s.Assert().Nil(err)
}

func (s *EndpointTestSuite) TestListenAndServe() {
	errChan := make(chan error)
	go func() { errChan <- s.e.ListenAndServe() }()

	// It should not exit "immediately"
	time.Sleep(time.Millisecond * 1)
	select {
	case err := <-errChan:
		require.NoError(s.T(), err)
	default:
		break
	}

	// It should shutdown cleanly
	s.e.Shutdown()
	err := <-errChan
	require.NoError(s.T(), err)
}
