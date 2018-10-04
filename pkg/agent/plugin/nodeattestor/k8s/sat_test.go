package k8s

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/stretchr/testify/suite"
)

func TestSATAttestorPlugin(t *testing.T) {
	suite.Run(t, new(SATAttestorSuite))
}

type SATAttestorSuite struct {
	suite.Suite

	dir      string
	attestor *nodeattestor.BuiltIn
}

func (s *SATAttestorSuite) SetupTest() {
	var err error
	s.dir, err = ioutil.TempDir("", "spire-k8s-sat-test-")
	s.Require().NoError(err)

	s.newAttestor()
	s.configure(SATAttestorConfig{})
}

func (s *SATAttestorSuite) TestFetchAttestationDataNotConfigured() {
	s.newAttestor()
	s.requireFetchError("k8s-sat: not configured")
}

func (s *SATAttestorSuite) TestFetchAttestationDataNoToken() {
	s.configure(SATAttestorConfig{
		TokenPath: s.joinPath("token"),
	})
	s.requireFetchError("unable to get token value")
}

func (s *SATAttestorSuite) TestFetchAttestationDataSuccess() {
	s.configure(SATAttestorConfig{
		TokenPath: s.writeValue("token", "TOKEN"),
	})

	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)

	// assert attestation data
	s.Require().Equal("spiffe://example.org/spire/agent/k8s_sat/UUID", resp.SpiffeId)
	s.Require().NotNil(resp.AttestationData)
	s.Require().Equal("k8s_sat", resp.AttestationData.Type)
	s.Require().JSONEq(`{
		"uuid": "UUID",
		"token": "TOKEN"
	}`, string(resp.AttestationData.Data))

	// node attestor should return EOF now
	_, err = stream.Recv()
	s.Require().Equal(io.EOF, err)
}

func (s *SATAttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{},
		Configuration: "blah",
	})
	s.requireErrorContains(err, "k8s-sat: unable to decode configuration")
	s.Require().Nil(resp)

	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.requireErrorContains(err, "k8s-sat: global configuration is required")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.Require().EqualError(err, "k8s-sat: global configuration missing trust domain")
	s.Require().Nil(resp)

	// success
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *SATAttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *SATAttestorSuite) newAttestor() {
	attestor := NewSATAttestorPlugin()
	attestor.hooks.newUUID = func() string {
		return "UUID"
	}
	s.attestor = nodeattestor.NewBuiltIn(attestor)
}

func (s *SATAttestorSuite) configure(config SATAttestorConfig) {
	_, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
		Configuration: fmt.Sprintf(`token_path = %q`, config.TokenPath),
	})
	s.Require().NoError(err)

}
func (s *SATAttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *SATAttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	s.Require().NoError(err)
	err = ioutil.WriteFile(valuePath, []byte(data), 0644)
	s.Require().NoError(err)
	return valuePath
}

func (s *SATAttestorSuite) requireFetchError(contains string) {
	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.requireErrorContains(err, contains)
	s.Require().Nil(resp)
}

func (s *SATAttestorSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}
