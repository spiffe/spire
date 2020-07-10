package aws

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
)

const (
	awsAgentID = "spiffe://example.org/spire/agent/aws_iid/ACCOUNT/REGION/INSTANCE"
)

func TestIIDResolver(t *testing.T) {
	spiretest.Run(t, new(IIDResolverSuite))
}

type IIDResolverSuite struct {
	spiretest.Suite

	env      map[string]string
	resolver noderesolver.Plugin
	logHook  *test.Hook
}

func (s *IIDResolverSuite) SetupTest() {
	s.env = make(map[string]string)
	s.newResolver()
	s.configureResolver()
}

func (s *IIDResolverSuite) TestResolveWhenNotConfigured() {
	s.newResolver()
	s.assertResolveSuccess()
}

func (s *IIDResolverSuite) TestResolve() {
	// nothing to resolve
	resp, err := s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{})
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.Map)

	// not an agent ID
	resp, err = s.doResolve("spiffe://example.org/spire/server")
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.Map["spiffe://example.org/spire/server"])

	// not an IID-based agent ID
	resp, err = s.doResolve("spiffe://example.org/spire/agent/whatever")
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().Empty(resp.Map["spiffe://example.org/spire/agent/whatever"])
}

func (s *IIDResolverSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	// succeeds with no credentials
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	// access id but no secret
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		access_key_id = "ACCESSKEYID"
		`})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	// secret but no access id
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		secret_access_key = "SECRETACCESSKEY"
		`})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	// envvars
	s.env["AWS_ACCESS_KEY_ID"] = "ACCESSKEYID"
	s.env["AWS_SECRET_ACCESS_KEY"] = "SECRETACCESSKEY"
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
	delete(s.env, "AWS_ACCESS_KEY_ID")
	delete(s.env, "AWS_SECRET_ACCESS_KEY")

	// access id/secret credentials
	s.configureResolver()
}

func (s *IIDResolverSuite) TestGetPluginInfo() {
	resp, err := s.resolver.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *IIDResolverSuite) newResolver() {
	resolver := New()
	log, hook := test.NewNullLogger()
	s.logHook = hook
	s.LoadPlugin(builtin(resolver), &s.resolver, spiretest.Logger(log))
}

func (s *IIDResolverSuite) configureResolver() {
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		access_key_id = "ACCESSKEYID"
		secret_access_key = "SECRETACCESSKEY"
		`})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
	spiretest.AssertLogs(s.T(), []*logrus.Entry{s.logHook.LastEntry()},
		[]spiretest.LogEntry{
			{
				Level:   logrus.WarnLevel,
				Message: "Usage of deprecated plugin detected.",
				Data: logrus.Fields{
					telemetry.PluginName:    caws.PluginName,
					telemetry.PluginType:    noderesolver.Type,
					telemetry.SubsystemName: telemetry.PluginBuiltIn + "." + caws.PluginName,
				},
			},
		})
}

func (s *IIDResolverSuite) assertResolveSuccess() {
	expected := &noderesolver.ResolveResponse{}
	actual, err := s.doResolve(awsAgentID)
	s.Require().NoError(err)
	s.Require().Equal(expected, actual)
}

func (s *IIDResolverSuite) doResolve(spiffeID string) (*noderesolver.ResolveResponse, error) {
	return s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{spiffeID},
	})
}
