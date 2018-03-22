package bundle

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/proto/api/registration"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/suite"
)

type ShowTestSuite struct {
	suite.Suite
	mockClient *mock_registration.MockRegistrationClient
}

func TestShowTestSuite(t *testing.T) {
	suite.Run(t, new(ShowTestSuite))
}

func (s *ShowTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	defer mockCtrl.Finish()

	s.mockClient = mock_registration.NewMockRegistrationClient(mockCtrl)
}

func (s *ShowTestSuite) TestRunWithDefaultArgs() {
	cli := &showCLI{
		newRegistrationClient: func(addr string) (registration.RegistrationClient, error) {
			return s.mockClient, nil
		},
		writer: &bytes.Buffer{},
	}

	ca, _, err := util.LoadCAFixture()
	s.Require().Nil(err)

	resp := &registration.Bundle{Asn1Data: ca.Raw}
	s.mockClient.EXPECT().FetchBundle(context.TODO(), &common.Empty{}).Return(resp, nil)

	args := []string{}
	s.Require().Equal(0, cli.Run(args))

	bundleASN1 := transcodeBundleFromPEMToASN1DER(cli.writer.(*bytes.Buffer).Bytes())

	s.Assert().Equal(ca.Raw, bundleASN1)
}

func (s *ShowTestSuite) TestRunWithDefaultArgsAndFailedNewRegClient() {
	expecterError := errors.New("error creating client")

	cli := &showCLI{
		newRegistrationClient: func(addr string) (registration.RegistrationClient, error) {
			return nil, expecterError
		},
	}

	stdOutRedir := &util.OutputRedirection{}
	err := stdOutRedir.Start(os.Stdout)
	s.Require().Nil(err)

	args := []string{}
	s.Require().Equal(1, cli.Run(args))

	output, err := stdOutRedir.Finish()
	s.Require().Nil(err)

	s.Assert().Equal(output, fmt.Sprintln(expecterError.Error()))
}

func (s *ShowTestSuite) TestRunWithDefaultArgsAndFailedFetchBundle() {
	expecterError := errors.New("error fetching bundle")

	cli := &showCLI{
		newRegistrationClient: func(addr string) (registration.RegistrationClient, error) {
			return s.mockClient, nil
		},
	}

	s.mockClient.EXPECT().FetchBundle(context.TODO(), &common.Empty{}).Return(nil, expecterError)

	stdOutRedir := &util.OutputRedirection{}
	err := stdOutRedir.Start(os.Stdout)
	s.Require().Nil(err)

	args := []string{}
	s.Require().Equal(1, cli.Run(args))

	output, err := stdOutRedir.Finish()
	s.Require().Nil(err)

	s.Assert().Equal(output, fmt.Sprintln(expecterError.Error()))
}

func (s *ShowTestSuite) TestRunWithArgs() {
	expecterAddr := "localhost:8080"

	cli := &showCLI{
		newRegistrationClient: func(addr string) (registration.RegistrationClient, error) {
			s.Assert().Equal(expecterAddr, addr)
			return s.mockClient, nil
		},
	}

	resp := &registration.Bundle{}
	s.mockClient.EXPECT().FetchBundle(context.TODO(), &common.Empty{}).Return(resp, nil)

	args := []string{"-serverAddr", expecterAddr}
	s.Require().Equal(0, cli.Run(args))
}

func (s *ShowTestSuite) TestRunWithWrongArgs() {
	cli := &showCLI{
		newRegistrationClient: func(addr string) (registration.RegistrationClient, error) {
			return s.mockClient, nil
		},
	}

	resp := &registration.Bundle{}
	s.mockClient.EXPECT().FetchBundle(context.TODO(), &common.Empty{}).Return(resp, nil)

	stdOutRedir := util.OutputRedirection{}
	stdErrRedir := util.OutputRedirection{}
	err := stdOutRedir.Start(os.Stdout)
	s.Require().Nil(err)
	err = stdErrRedir.Start(os.Stderr)
	s.Require().Nil(err)

	args := []string{"-someArg", "someValue"}
	s.Require().Equal(1, cli.Run(args))

	output, err := stdOutRedir.Finish()
	s.Require().Nil(err)
	errOutput, err := stdErrRedir.Finish()
	s.Require().Nil(err)

	expectedOutput := "flag provided but not defined: -someArg\n"

	expectedErrOutput := "flag provided but not defined: -someArg\n" +
		"Usage of bundle show:\n" +
		"  -serverAddr string\n" +
		"    \tAddress of the SPIRE server (default \"localhost:8081\")\n"

	s.Assert().Equal(expectedOutput, output)
	s.Assert().Equal(expectedErrOutput, errOutput)
}

func transcodeBundleFromPEMToASN1DER(pemBundle []byte) []byte {
	result := &bytes.Buffer{}
	for p, r := pem.Decode(pemBundle); p != nil; p, r = pem.Decode(r) {
		result.Write(p.Bytes)
	}
	return result.Bytes()
}
