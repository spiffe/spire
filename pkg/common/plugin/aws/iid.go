package aws

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
)

const (
	// PluginName for AWS IID
	PluginName = "aws_iid"
	// AccessKeyIDVarName env var name for AWS access key ID
	AccessKeyIDVarName = "AWS_ACCESS_KEY_ID"
	// SecretAccessKeyVarName env car name for AWS secret access key
	SecretAccessKeyVarName = "AWS_SECRET_ACCESS_KEY" //nolint: gosec // false positive
)

var (
	IidErrorClass   = errs.Class("aws-iid")
	InstanceFilters = []*ec2.Filter{
		{
			Name: aws.String("instance-state-name"),
			Values: []*string{
				aws.String("pending"),
				aws.String("running"),
			},
		},
	}
	iidError                 = IidErrorClass
	DefaultNewClientCallback = newClient
)

// IIDAttestationData AWS IID attestation data
type IIDAttestationData struct {
	Document  string `json:"document"`
	Signature string `json:"signature"`
}

// AttestationStepError error with attestation
func AttestationStepError(step string, cause error) error {
	return iidError.New("attempted attestation but an error occurred %s: %w", step, cause)
}

func ResolveSelectors(ctx context.Context, client Client, instanceID string) (*common.Selectors, error) {
	resp, err := client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(instanceID)},
		Filters:     InstanceFilters,
	})
	if err != nil {
		return nil, iidError.Wrap(err)
	}

	selectorSet := map[string]bool{}
	addSelectors := func(values []string) {
		for _, value := range values {
			selectorSet[value] = true
		}
	}

	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			addSelectors(resolveTags(instance.Tags))
			addSelectors(resolveSecurityGroups(instance.SecurityGroups))
			if instance.IamInstanceProfile != nil && instance.IamInstanceProfile.Arn != nil {
				instanceProfileName, err := instanceProfileNameFromArn(*instance.IamInstanceProfile.Arn)
				if err != nil {
					return nil, err
				}
				output, err := client.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{
					InstanceProfileName: aws.String(instanceProfileName),
				})
				if err != nil {
					return nil, iidError.Wrap(err)
				}
				addSelectors(resolveInstanceProfile(output.InstanceProfile))
			}
		}
	}

	// build and sort selectors
	selectors := new(common.Selectors)
	for value := range selectorSet {
		selectors.Entries = append(selectors.Entries, &common.Selector{
			Type:  PluginName,
			Value: value,
		})
	}
	util.SortSelectors(selectors.Entries)

	return selectors, nil
}

func resolveTags(tags []*ec2.Tag) []string {
	values := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag != nil {
			values = append(values, fmt.Sprintf("tag:%s:%s", aws.StringValue(tag.Key), aws.StringValue(tag.Value)))
		}
	}
	return values
}

func resolveSecurityGroups(sgs []*ec2.GroupIdentifier) []string {
	values := make([]string, 0, len(sgs)*2)
	for _, sg := range sgs {
		if sg != nil {
			values = append(values,
				fmt.Sprintf("sg:id:%s", aws.StringValue(sg.GroupId)),
				fmt.Sprintf("sg:name:%s", aws.StringValue(sg.GroupName)),
			)
		}
	}
	return values
}

func resolveInstanceProfile(instanceProfile *iam.InstanceProfile) []string {
	if instanceProfile == nil {
		return nil
	}
	values := make([]string, 0, len(instanceProfile.Roles))
	for _, role := range instanceProfile.Roles {
		if role != nil && role.Arn != nil {
			values = append(values, fmt.Sprintf("iamrole:%s", aws.StringValue(role.Arn)))
		}
	}
	return values
}

var reInstanceProfileARNResource = regexp.MustCompile(`instance-profile[/:](.+)`)

func instanceProfileNameFromArn(profileArn string) (string, error) {
	a, err := arn.Parse(profileArn)
	if err != nil {
		return "", iidError.Wrap(err)
	}
	m := reInstanceProfileARNResource.FindStringSubmatch(a.Resource)
	if m == nil {
		return "", iidError.New("arn is not for an instance profile")
	}

	return m[1], nil
}
