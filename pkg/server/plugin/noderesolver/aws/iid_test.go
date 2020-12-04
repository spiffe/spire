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
}

func (s *IIDResolverSuite) TestResolveWhenNotConfigured() {
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
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		access_key_id = "ACCESSKEYID"
		secret_access_key = "SECRETACCESSKEY"
		`})
	s.Require().NoError(err)
	s.RequireProtoEqual(resp, &plugin.ConfigureResponse{})
	spiretest.AssertLogs(s.T(), []*logrus.Entry{s.logHook.LastEntry()},
		[]spiretest.LogEntry{
			{
				Level:   logrus.WarnLevel,
				Message: "The aws_iid resolver has been subsumed by the aws_iid node attestor and will be removed in a future release. Please remove it from your configuration.",
				Data: logrus.Fields{
					telemetry.SubsystemName: telemetry.PluginBuiltIn + "." + caws.PluginName,
				},
			},
		})
}

func (s *IIDResolverSuite) TestGetPluginInfo() {
	resp, err := s.resolver.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.RequireProtoEqual(resp, &plugin.GetPluginInfoResponse{})
}

func (s *IIDResolverSuite) newResolver() {
	resolver := New()
	log, hook := test.NewNullLogger()
	s.logHook = hook
	s.LoadPlugin(builtin(resolver), &s.resolver, spiretest.Logger(log))
}

func (s *IIDResolverSuite) assertResolveSuccess() {
	expected := &noderesolver.ResolveResponse{}
	actual, err := s.doResolve(awsAgentID)
	s.Require().NoError(err)
	s.RequireProtoEqual(expected, actual)
}

func (s *IIDResolverSuite) doResolve(spiffeID string) (*noderesolver.ResolveResponse, error) {
	return s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{spiffeID},
	})
}
