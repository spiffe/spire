package aws

import (
	"testing"

	"github.com/spiffe/spire/test/spiretest"
)

const (
	testInstanceProfileArn  = "arn:aws:iam::123412341234:instance-profile/nodes.test.k8s.local"
	testInstanceProfileName = "nodes.test.k8s.local"
)

func TestIIDResolver(t *testing.T) {
	spiretest.Run(t, new(IIDSuite))
}

type IIDSuite struct {
	spiretest.Suite
}

func (s *IIDSuite) TestInstanceProfileArnParsing() {
	// not an ARN
	_, err := instanceProfileNameFromArn("not-an-arn")
	s.Require().EqualError(err, "aws-iid: arn: invalid prefix")

	// not an instance profile ARN
	_, err = instanceProfileNameFromArn("arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment")
	s.Require().EqualError(err, "aws-iid: arn is not for an instance profile")

	name, err := instanceProfileNameFromArn(testInstanceProfileArn)
	s.Require().NoError(err)
	s.Require().Equal(testInstanceProfileName, name)
}
