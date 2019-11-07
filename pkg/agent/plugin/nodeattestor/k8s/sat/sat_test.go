package sat

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
)

func TestAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(AttestorSuite))
}

type AttestorSuite struct {
	spiretest.Suite

	dir      string
	attestor nodeattestor.Plugin
}

func (s *AttestorSuite) SetupTest() {
	s.dir = s.TempDir()

	s.newAttestor()
	s.configure(AttestorConfig{})
}

func (s *AttestorSuite) TearDownTest() {
	os.RemoveAll(s.dir)
}

func (s *AttestorSuite) TestFetchAttestationDataNotConfigured() {
	s.newAttestor()
	s.requireFetchError("k8s-sat: not configured")
}

func (s *AttestorSuite) TestFetchAttestationDataNoToken() {
	s.configure(AttestorConfig{
		TokenPath: s.joinPath("token"),
	})
	s.requireFetchError("unable to load token from")
}

func (s *AttestorSuite) TestFetchAttestationDataSuccess() {
	s.configure(AttestorConfig{
		TokenPath: s.writeValue("token", "TOKEN"),
	})

	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.Require().NoError(err)
	s.Require().NotNil(resp)

	// assert attestation data
	s.Require().NotNil(resp.AttestationData)
	s.Require().Equal("k8s_sat", resp.AttestationData.Type)
	s.Require().JSONEq(`{
		"cluster": "production",
		"token": "TOKEN"
	}`, string(resp.AttestationData.Data))

	// node attestor should return EOF now
	_, err = stream.Recv()
	s.Require().Equal(io.EOF, err)
}

func (s *AttestorSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{},
		Configuration: "blah",
	})
	s.RequireGRPCStatusContains(err, codes.Unknown, "k8s-sat: unable to decode configuration")
	s.Require().Nil(resp)

	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.RequireGRPCStatusContains(err, codes.Unknown, "k8s-sat: global configuration is required")
	s.Require().Nil(resp)

	// missing trust domain
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{}})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-sat: global configuration missing trust domain")
	s.Require().Nil(resp)

	// missing cluster
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.RequireGRPCStatus(err, codes.Unknown, "k8s-sat: configuration missing cluster")
	s.Require().Nil(resp)

	// success
	resp, err = s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
		Configuration: `cluster = "production"`,
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *AttestorSuite) TestGetPluginInfo() {
	resp, err := s.attestor.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *AttestorSuite) newAttestor() {
	s.LoadPlugin(BuiltIn(), &s.attestor)
}

func (s *AttestorSuite) configure(config AttestorConfig) {
	_, err := s.attestor.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{
			TrustDomain: "example.org",
		},
		Configuration: fmt.Sprintf(`
			cluster = "production"
			token_path = %q`, config.TokenPath),
	})
	s.Require().NoError(err)
}

func (s *AttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *AttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	s.Require().NoError(err)
	err = ioutil.WriteFile(valuePath, []byte(data), 0644)
	s.Require().NoError(err)
	return valuePath
}

func (s *AttestorSuite) requireFetchError(contains string) {
	stream, err := s.attestor.FetchAttestationData(context.Background())
	s.Require().NoError(err)
	s.Require().NotNil(stream)

	resp, err := stream.Recv()
	s.RequireErrorContains(err, contains)
	s.Require().Nil(resp)
}
