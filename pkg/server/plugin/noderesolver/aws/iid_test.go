package aws

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/stretchr/testify/suite"
	"github.com/zeebo/errs"
)

const (
	awsAgentID = "spiffe://example.org/spire/agent/aws_iid/ACCOUNT/REGION/INSTANCE"
)

func TestIIDResolver(t *testing.T) {
	suite.Run(t, new(IIDResolverSuite))
}

type IIDResolverSuite struct {
	suite.Suite

	env      map[string]string
	client   *fakeAWSClient
	resolver *noderesolver.BuiltIn
}

func (s *IIDResolverSuite) SetupTest() {
	s.env = make(map[string]string)
	s.client = new(fakeAWSClient)
	s.newResolver()
	s.configureResolver()
}

func (s *IIDResolverSuite) TestResolveWhenNotConfigured() {
	s.newResolver()
	s.assertResolveFailure(awsAgentID,
		`aws-iid: not configured`)
}

func (s *IIDResolverSuite) TestResolveRecreatesClientsOnConfigure() {
	// resolve once
	s.client.SetInstance(&ec2.Instance{})
	s.assertResolveSuccess()

	// fail the next client creation
	s.client = nil

	// reconfigure
	s.configureResolver()

	// make sure resolving failed because a new client was attempted to be made
	s.assertResolveFailure(awsAgentID, "YAY")
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

	// instance w/o tags or security groups or IAM
	s.client.SetInstance(&ec2.Instance{})
	s.assertResolveSuccess()

	// instance with tags
	s.client.SetInstance(&ec2.Instance{
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("KEY1"),
				Value: aws.String("VALUE1"),
			},
			{
				Key:   aws.String("KEY2"),
				Value: aws.String("VALUE2"),
			},
		},
	})
	s.assertResolveSuccess([]string{
		"tag:KEY1:VALUE1",
		"tag:KEY2:VALUE2",
	})

	// instance with security groups
	s.client.SetInstance(&ec2.Instance{
		SecurityGroups: []*ec2.GroupIdentifier{
			{
				GroupId:   aws.String("GROUPID1"),
				GroupName: aws.String("GROUPNAME1"),
			},
			{
				GroupId:   aws.String("GROUPID2"),
				GroupName: aws.String("GROUPNAME2"),
			},
		},
	})
	s.assertResolveSuccess([]string{
		"sg:id:GROUPID1",
		"sg:id:GROUPID2",
		"sg:name:GROUPNAME1",
		"sg:name:GROUPNAME2",
	})

	// instance with IAM role
	s.client.SetInstance(&ec2.Instance{
		IamInstanceProfile: &ec2.IamInstanceProfile{
			Arn: aws.String("INSTANCEPROFILE"),
		},
	})
	s.client.SetInstanceProfile(&iam.InstanceProfile{
		Roles: []*iam.Role{
			{Arn: aws.String("ROLE1")},
			{Arn: aws.String("ROLE2")},
		},
	})
	s.assertResolveSuccess([]string{
		"iamrole:ROLE1",
		"iamrole:ROLE2",
	})
}

func (s *IIDResolverSuite) TestConfigure() {
	// malformed configuration
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: "blah",
	})
	s.requireErrorContains(err, "aws-iid: unable to decode configuration")
	s.Require().Nil(resp)

	// succeeds with no credentials
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})

	// fails with access id but no secret
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		access_key_id = "ACCESSKEYID"
		`})
	s.Require().EqualError(err, "aws-iid: configuration missing secret access key, but has access key id")
	s.Require().Nil(resp)

	// fails with secret but no access id
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		secret_access_key = "SECRETACCESSKEY"
		`})
	s.Require().EqualError(err, "aws-iid: configuration missing access key id, but has secret access key")
	s.Require().Nil(resp)

	// success with envvars
	s.env[caws.AccessKeyIDVarName] = "ACCESSKEYID"
	s.env[caws.SecretAccessKeyVarName] = "SECRETACCESSKEY"
	resp, err = s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
	delete(s.env, caws.AccessKeyIDVarName)
	delete(s.env, caws.SecretAccessKeyVarName)

	// success with access id/secret credentials
	s.configureResolver()
}

func (s *IIDResolverSuite) TestGetPluginInfo() {
	resp, err := s.resolver.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *IIDResolverSuite) newResolver() {
	resolver := NewIIDResolverPlugin()
	resolver.hooks.getenv = func(key string) string {
		return s.env[key]
	}
	resolver.hooks.newClient = func(config *caws.SessionConfig, region string) (awsClient, error) {
		// assert that the right region is specified
		s.Require().Equal("REGION", region)

		// assert that the credentials are populated correctly
		s.Require().NotNil(config)
		s.Require().Equal(&caws.SessionConfig{
			AccessKeyID:     "ACCESSKEYID",
			SecretAccessKey: "SECRETACCESSKEY",
		}, config)

		// if s.client is nil, fail in a special way (see TestResolveRecreatesClientsOnConfigure)
		if s.client == nil {
			return nil, errors.New("YAY")
		}

		return s.client, nil
	}
	s.resolver = noderesolver.NewBuiltIn(resolver)
}

func (s *IIDResolverSuite) configureResolver() {
	resp, err := s.resolver.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		access_key_id = "ACCESSKEYID"
		secret_access_key = "SECRETACCESSKEY"
		`})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
}

func (s *IIDResolverSuite) requireErrorContains(err error, contains string) {
	s.Require().Error(err)
	s.Require().Contains(err.Error(), contains)
}

func (s *IIDResolverSuite) assertResolveSuccess(selectorValueSets ...[]string) {
	var selectorValues []string
	for _, values := range selectorValueSets {
		for _, value := range values {
			selectorValues = append(selectorValues, value)
		}
	}
	sort.Strings(selectorValues)
	selectors := &common.Selectors{}
	for _, selectorValue := range selectorValues {
		selectors.Entries = append(selectors.Entries, &common.Selector{
			Type:  "aws_iid",
			Value: selectorValue,
		})
	}
	expected := &noderesolver.ResolveResponse{
		Map: map[string]*common.Selectors{
			awsAgentID: selectors,
		},
	}
	actual, err := s.doResolve(awsAgentID)
	s.Require().NoError(err)
	s.Require().Equal(expected, actual)
}

func (s *IIDResolverSuite) assertResolveFailure(spiffeID, containsErr string) {
	resp, err := s.doResolve(spiffeID)
	s.requireErrorContains(err, containsErr)
	s.Require().Nil(resp)
}

func (s *IIDResolverSuite) doResolve(spiffeID string) (*noderesolver.ResolveResponse, error) {
	return s.resolver.Resolve(context.Background(), &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{spiffeID},
	})
}

type fakeAWSClient struct {
	instance        *ec2.Instance
	instanceProfile *iam.InstanceProfile
}

func (c *fakeAWSClient) SetInstance(instance *ec2.Instance) {
	c.instance = instance
}

func (c *fakeAWSClient) SetInstanceProfile(instanceProfile *iam.InstanceProfile) {
	c.instanceProfile = instanceProfile
}

func (c *fakeAWSClient) DescribeInstancesWithContext(_ aws.Context, input *ec2.DescribeInstancesInput, _ ...request.Option) (*ec2.DescribeInstancesOutput, error) {
	switch {
	case input.InstanceIds == nil:
		return nil, errs.New("bad request: instance ids is nil")
	case len(input.InstanceIds) == 0:
		return nil, errs.New("bad request: instance ids is empty")
	case input.InstanceIds[0] == nil:
		return nil, errs.New("bad request: instance id is nil")
	case (*input.InstanceIds[0]) != "INSTANCE":
		return nil, errs.New("instance not found")
	case c.instance == nil:
		return nil, errs.New("misconfigured test: instance is nil")
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					c.instance,
				},
			},
		},
	}, nil
}

func (c *fakeAWSClient) GetInstanceProfileWithContext(_ aws.Context, input *iam.GetInstanceProfileInput, _ ...request.Option) (*iam.GetInstanceProfileOutput, error) {
	switch {
	case input.InstanceProfileName == nil:
		return nil, errs.New("bad request: instance profile name is nil")
	case (*input.InstanceProfileName) == "":
		return nil, errs.New("bad request: instance profile name id empty")
	case (*input.InstanceProfileName) != "INSTANCEPROFILE":
		return nil, errs.New("instance profile not found")
	case c.instanceProfile == nil:
		return nil, errs.New("misconfigured test: instance profile is nil")
	}
	return &iam.GetInstanceProfileOutput{
		InstanceProfile: c.instanceProfile,
	}, nil
}
