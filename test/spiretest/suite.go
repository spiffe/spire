package spiretest

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

func Run(t *testing.T, s suite.TestingSuite) {
	suite.Run(t, s)
}

type Suite struct {
	suite.Suite
}

func (s *Suite) Cleanup(cleanup func()) {
	s.T().Cleanup(cleanup)
}

func (s *Suite) TempDir() string {
	return TempDir(s.T())
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

func (s *Suite) RequireProtoListEqual(expected, actual any) {
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

func (s *Suite) AssertProtoListEqual(expected, actual any) bool {
	s.T().Helper()
	return AssertProtoListEqual(s.T(), expected, actual)
}

func (s *Suite) AssertProtoEqual(expected, actual proto.Message, msgAndArgs ...any) bool {
	s.T().Helper()
	return AssertProtoEqual(s.T(), expected, actual, msgAndArgs...)
}
