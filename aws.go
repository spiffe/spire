package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/noderesolver"

	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"net/url"
	"path"
	"sync"
)

type AWSResolver struct {
	accessId    string
	secret      string
	sessionId   string
	resolutions map[string]*common.Selectors
	ec2Clients  []ec2iface.EC2API
	iamClient   iamiface.IAMAPI
	mtx         sync.RWMutex
}

type AWSResolverConfig struct {
	AccessId  string `hcl:"access_id"`
	Secret    string `hcl:"secret"`
	SessionId string `hcl:session_id`
}

func (a *AWSResolver) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &AWSResolverConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	// Set local vars from config struct
	a.accessId = config.AccessId
	a.secret = config.Secret
	a.sessionId = config.SessionId

	return resp, err
}

func (a *AWSResolver) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (a *AWSResolver) Resolve(physicalSpiffeIdList []string) (resolutions map[string]*common.Selectors, err error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.resolutions = make(map[string]*common.Selectors)

	for _, spiffeID := range physicalSpiffeIdList {
		var instanceIds []*string
		instanceId, err := a.instanceID(spiffeID)
		if err != nil {
			return nil, err
		}
		instanceIds = append(instanceIds, aws.String(instanceId))
		err = a.setEC2Clients()
		if err != nil {
			return nil, err
		}
		for _, ec2Client := range a.ec2Clients {
			filters := []*ec2.Filter{
				{
					Name: aws.String("instance-state-name"),
					Values: []*string{
						aws.String("pending"),
						aws.String("running"),
					},
				},
			}
			resv, err := ec2Client.DescribeInstances(&ec2.DescribeInstancesInput{
				InstanceIds: instanceIds,
				Filters:     filters})
			if err != nil && err.(awserr.Error).Code() != "InvalidInstanceID.NotFound" {
				return nil, err
			}
			if err == nil {
				a.resolveTags(resv.Reservations[0].Instances[0].Tags, spiffeID)
				a.resolveSecurityGroups(resv.Reservations[0].Instances[0].SecurityGroups, spiffeID)
				if resv.Reservations[0].Instances[0].IamInstanceProfile != nil {
					ar, _ := arn.Parse(aws.StringValue(resv.Reservations[0].Instances[0].IamInstanceProfile.Arn))
					err = a.resolveIAMRole(aws.String(path.Base(ar.Resource)), spiffeID)
				}
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return a.resolutions, nil
}

func (a *AWSResolver) resolveTags(tags []*ec2.Tag, spiffeID string) {
	for _, tag := range tags {
		if _, ok := a.resolutions[spiffeID]; ok {
			a.resolutions[spiffeID].Entries = append(a.resolutions[spiffeID].Entries,
				&common.Selector{
					Type:  "aws",
					Value: fmt.Sprintf("tag:%s:%s", aws.StringValue(tag.Key), aws.StringValue(tag.Value))})
		} else {
			a.resolutions[spiffeID] = &common.Selectors{
				[]*common.Selector{
					{
						Type:  "aws",
						Value: fmt.Sprintf("tag:%s:%s", aws.StringValue(tag.Key), aws.StringValue(tag.Value))},
				},
			}
		}
	}
}

func (a *AWSResolver) resolveSecurityGroups(sgs []*ec2.GroupIdentifier, spiffeID string) {
	for _, sg := range sgs {
		if _, ok := a.resolutions[spiffeID]; ok {
			a.resolutions[spiffeID].Entries = append(a.resolutions[spiffeID].Entries,
				&common.Selector{
					Type:  "aws",
					Value: fmt.Sprintf("sg:id:%s", aws.StringValue(sg.GroupId))})
			a.resolutions[spiffeID].Entries = append(a.resolutions[spiffeID].Entries,
				&common.Selector{
					Type: "aws", Value: fmt.Sprintf("sg:name:%s", aws.StringValue(sg.GroupName))})
		} else {
			a.resolutions[spiffeID] = &common.Selectors{
				[]*common.Selector{
					{
						Type: "aws", Value: fmt.Sprintf("sg:id:%s", aws.StringValue(sg.GroupId))},
					{
						Type: "aws", Value: fmt.Sprintf("sg:name:%s", aws.StringValue(sg.GroupName))},
				},
			}
		}
	}
}

func (a *AWSResolver) resolveIAMRole(arn *string, spiffeID string) error {
	output, err := a.iamClient.GetInstanceProfile(&iam.GetInstanceProfileInput{InstanceProfileName: arn})
	if err != nil {
		return err
	}
	for _, role := range output.InstanceProfile.Roles {
		if _, ok := a.resolutions[spiffeID]; ok {
			a.resolutions[spiffeID].Entries = append(a.resolutions[spiffeID].Entries,
				&common.Selector{
					Type: "aws", Value: fmt.Sprintf("iamrole:%s", aws.StringValue(role.Arn))})
		} else {
			a.resolutions[spiffeID] = &common.Selectors{
				[]*common.Selector{
					{
						Type: "aws", Value: fmt.Sprintf("iamrole:%s", aws.StringValue(role.Arn)),
					},
				},
			}
		}
	}
	return nil
}

func (a *AWSResolver) instanceID(spiffeID string) (instanceId string, err error) {
	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return
	}
	instanceId = path.Base(spiffeURI.Path)

	return
}

func (a *AWSResolver) setEC2Clients() error {
	var conf *aws.Config

	if a.secret != "" && a.accessId != "" {
		creds := credentials.NewStaticCredentials(a.accessId, a.secret, a.sessionId)
		conf = &aws.Config{Credentials: creds}
	} else {
		conf = aws.NewConfig()
	}

	sess, err := session.NewSession(conf)
	if err != nil {
		return err
	}
	ec := ec2.New(sess)
	output, err := ec.DescribeRegions(&ec2.DescribeRegionsInput{})
	for _, region := range output.Regions {
		conf.Region = region.RegionName
		sess, err := session.NewSession(conf)
		if err != nil {
			return err
		}
		a.iamClient = iam.New(sess)
		a.ec2Clients = append(a.ec2Clients, ec2.New(sess))

	}
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: noderesolver.Handshake,
		Plugins: map[string]plugin.Plugin{
			"nr_aws": noderesolver.NodeResolverPlugin{NodeResolverImpl: &AWSResolver{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})

}
