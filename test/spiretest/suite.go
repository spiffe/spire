package spiretest

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
)

type suiteMethods interface {
	initSuite()
	closeSuite()
}

func Run(t *testing.T, s suite.TestingSuite) {
	if m, ok := s.(suiteMethods); ok {
		m.initSuite()
		defer m.closeSuite()
	}
	suite.Run(t, s)
}

type Suite struct {
	suite.Suite
	init bool

	closers []func()
}

func (s *Suite) initSuite() {
	s.init = true
}

func (s *Suite) closeSuite() {
	for _, closer := range s.closers {
		closer()
	}
}

func (s *Suite) checkInit() {
	if !s.init {
		s.Require().FailNow("Suite must be run with spiretest.Run()")
	}
}

func (s *Suite) AppendCloser(closer func()) {
	s.checkInit()
	s.closers = append(s.closers, closer)
}

func (s *Suite) TempDir() string {
	dir, err := ioutil.TempDir("", "spire-test-")
	s.Require().NoError(err)
	s.AppendCloser(func() {
		os.RemoveAll(dir)
	})
	return dir
}

func (s *Suite) LoadPlugin(builtin catalog.Plugin, x interface{}, opts ...PluginOption) {
	s.T().Helper()
	closer := LoadPlugin(s.T(), builtin, x, opts...)
	s.AppendCloser(closer)
}

func (s *Suite) RequireErrorContains(err error, contains string) {
	s.T().Helper()
	RequireErrorContains(s.T(), err, contains)
}

func (s *Suite) RequireGRPCStatus(err error, code codes.Code, message string) {
	s.T().Helper()
	RequireGRPCStatus(s.T(), err, code, message)
}

func (s *Suite) RequireGRPCStatusContains(err error, code codes.Code, contains string) {
	s.T().Helper()
	RequireGRPCStatusContains(s.T(), err, code, contains)
}

func (s *Suite) RequireProtoListEqual(expected, actual interface{}) {
	s.T().Helper()
	RequireProtoListEqual(s.T(), expected, actual)
}

func (s *Suite) RequireProtoEqual(expected, actual proto.Message) {
	s.T().Helper()
	RequireProtoEqual(s.T(), expected, actual)
}

func (s *Suite) AssertErrorContains(err error, contains string) bool {
	s.T().Helper()
	return AssertErrorContains(s.T(), err, contains)
}

func (s *Suite) AssertGRPCStatus(err error, code codes.Code, message string) bool {
	s.T().Helper()
	return AssertGRPCStatus(s.T(), err, code, message)
}

func (s *Suite) AssertGRPCStatusContains(err error, code codes.Code, contains string) bool {
	s.T().Helper()
	return AssertGRPCStatusContains(s.T(), err, code, contains)
}

func (s *Suite) AssertProtoListEqual(expected, actual interface{}) bool {
	s.T().Helper()
	return AssertProtoListEqual(s.T(), expected, actual)
}

func (s *Suite) AssertProtoEqual(expected, actual proto.Message) bool {
	s.T().Helper()
	return AssertProtoEqual(s.T(), expected, actual)
}
