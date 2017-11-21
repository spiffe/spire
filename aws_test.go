package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAWSResolver_Resolve(t *testing.T) {
	tests := []struct {
		name              string
		instance          *ec2.Instance
		expectedSelectors *common.Selectors
	}{
		{"testTagAndIAMResolution",
			&ec2.Instance{
				IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String(
					"arn:aws:iam::123456789012:instance-profile/application_abc/component_xyz/Webserver")},
				Tags: []*ec2.Tag{{Key: aws.String("testTag"), Value: aws.String("testValue")}},
			},
			&common.Selectors{
				Entries: []*common.Selector{
					{Type: "aws",
						Value: fmt.Sprintf("tag:%s:%s", "testTag", "testValue")},
					{Type: "aws",
						Value: fmt.Sprintf("iamrole:%s", "testRole")},
				},
			},
		},

		{
			"testSecurityGroupAndIAMResolution",
			&ec2.Instance{
				IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String(
					"arn:aws:iam::123456789012:instance-profile/application_abc/component_xyz/Webserver")},
				SecurityGroups: []*ec2.GroupIdentifier{
					{GroupId: aws.String("testId"), GroupName: aws.String("testName")}},
			},
			&common.Selectors{
				Entries: []*common.Selector{
					{Type: "aws",
						Value: fmt.Sprintf("sg:id:%s", "testId")},
					{Type: "aws",
						Value: fmt.Sprintf("sg:name:%s", "testName")},
					{Type: "aws",
						Value: fmt.Sprintf("iamrole:%s", "testRole")},
				},
			},
		},
		{
			"testIAMSecurityGroupAndTagResolution",
			&ec2.Instance{
				IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String(
					"arn:aws:iam::123456789012:instance-profile/application_abc/component_xyz/Webserver")},
				SecurityGroups: []*ec2.GroupIdentifier{
					{GroupId: aws.String("testId"), GroupName: aws.String("testName")}},
				Tags: []*ec2.Tag{{Key: aws.String("testTag"), Value: aws.String("testValue")}},
			},
			&common.Selectors{
				Entries: []*common.Selector{{Type: "aws",
					Value: fmt.Sprintf("tag:%s:%s", "testTag", "testValue")},
					{Type: "aws",
						Value: fmt.Sprintf("sg:id:%s", "testId")},
					{Type: "aws",
						Value: fmt.Sprintf("sg:name:%s", "testName")},
					{Type: "aws",
						Value: fmt.Sprintf("iamrole:%s", "testRole")},
				},
			},
		},
		{
			"testIAMOnlyResolution",
			&ec2.Instance{
				IamInstanceProfile: &ec2.IamInstanceProfile{Arn: aws.String(
					"arn:aws:iam::123456789012:instance-profile/application_abc/component_xyz/Webserver")}},
			&common.Selectors{
				Entries: []*common.Selector{{
					Type:  "aws",
					Value: fmt.Sprintf("iamrole:%s", "testRole")},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ec2mock := NewMockEC2API(ctrl)
			iammock := NewMockIAMAPI(ctrl)
			ec2mock.EXPECT().DescribeInstances(gomock.Any()).Return(
				&ec2.DescribeInstancesOutput{
					Reservations: []*ec2.Reservation{{Instances: []*ec2.Instance{test.instance}}}}, nil)
			ec2mock.EXPECT().DescribeInstances(gomock.Any()).Return(
				&ec2.DescribeInstancesOutput{
					Reservations: []*ec2.Reservation{{Instances: []*ec2.Instance{test.instance}}}}, nil)

			iammock.EXPECT().GetInstanceProfile(gomock.Any()).Return(
				&iam.GetInstanceProfileOutput{
					InstanceProfile: &iam.InstanceProfile{
						Roles: []*iam.Role{{Arn: aws.String("testRole")}},
					}}, nil)
			iammock.EXPECT().GetInstanceProfile(gomock.Any()).Return(
				&iam.GetInstanceProfileOutput{
					InstanceProfile: &iam.InstanceProfile{
						Roles: []*iam.Role{{Arn: aws.String("testRole")}},
					}}, nil)
			ar := &AWSResolver{
				ec2Clients: []ec2iface.EC2API{ec2mock},
				iamClient:  iammock,
			}
			ar.Resolve([]string{
				"spiffe://example.org/spire-agent/i-12345",
				"spiffe://example.org/spire-agent/i-adsfasdf"})

			assert.Equal(
				t,
				ar.resolutions["spiffe://example.org/spire-agent/i-12345"],
				test.expectedSelectors)
			assert.Equal(
				t,
				ar.resolutions["spiffe://example.org/spire-agent/i-adsfasdf"],
				test.expectedSelectors)
		})
	}
}

func TestAWSResolver_Configure(t *testing.T) {
	tests := []struct {
		name       string
		access_id  string
		secret     string
		session_id string
	}{
		{
			name:       "TestEmptyConfiguration",
			access_id:  "",
			secret:     "",
			session_id: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ar := &AWSResolver{}
			conf := fmt.Sprintf(
				`access_id = "%s"
				secret= "%s"
				session_id="%s"`,
				test.access_id,
				test.secret,
				test.session_id)

			ar.Configure(&plugin.ConfigureRequest{conf})
			assert.Equal(t, ar.accessId, test.access_id)
			assert.Equal(t, ar.secret, test.secret)
			assert.Equal(t, ar.sessionId, test.session_id)

		})
	}
}
