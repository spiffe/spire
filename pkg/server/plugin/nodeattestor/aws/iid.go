package aws

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	awsTimeout      = 5 * time.Second
	instanceFilters = []*ec2.Filter{
		{
			Name: aws.String("instance-state-name"),
			Values: []*string{
				aws.String("pending"),
				aws.String("running"),
			},
		},
	}
)

const (
	maxSecondsBetweenDeviceAttachments int64 = 60
	// accessKeyIDVarName env var name for AWS access key ID
	accessKeyIDVarName = "AWS_ACCESS_KEY_ID"
	// secretAccessKeyVarName env car name for AWS secret access key
	secretAccessKeyVarName = "AWS_SECRET_ACCESS_KEY" //nolint: gosec // false positive
)

// BuiltIn creates a new built-in plugin
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(caws.PluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// IIDAttestorPlugin implements node attestation for agents running in aws.
type IIDAttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	config  *IIDAttestorConfig
	mtx     sync.RWMutex
	clients *clientsCache

	// test hooks
	hooks struct {
		getAWSCAPublicKey func() (*rsa.PublicKey, error)
		getenv            func(string) string
	}

	log hclog.Logger
}

// IIDAttestorConfig holds hcl configuration for IID attestor plugin
type IIDAttestorConfig struct {
	SessionConfig                   `hcl:",squash"`
	SkipBlockDevice                 bool     `hcl:"skip_block_device"`
	DisableInstanceProfileSelectors bool     `hcl:"disable_instance_profile_selectors"`
	LocalValidAcctIDs               []string `hcl:"account_ids_for_local_validation"`
	AgentPathTemplate               string   `hcl:"agent_path_template"`
	AssumeRole                      string   `hcl:"assume_role"`
	pathTemplate                    *agentpathtemplate.Template
	trustDomain                     spiffeid.TrustDomain
	awsCAPublicKey                  *rsa.PublicKey
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	p := &IIDAttestorPlugin{}
	p.clients = newClientsCache(defaultNewClientCallback)
	p.hooks.getAWSCAPublicKey = getAWSCAPublicKey
	p.hooks.getenv = os.Getenv
	return p
}

// Attest implements the server side logic for the aws iid node attestation plugin.
func (p *IIDAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	c, err := p.getConfig()
	if err != nil {
		return err
	}

	attestationData, err := unmarshalAndValidateIdentityDocument(payload, c.awsCAPublicKey)
	if err != nil {
		return err
	}

	inTrustAcctList := false
	for _, id := range c.LocalValidAcctIDs {
		if attestationData.AccountID == id {
			inTrustAcctList = true
			break
		}
	}

	awsClient, err := p.clients.getClient(attestationData.Region, attestationData.AccountID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get client: %v", err)
	}

	ctx, cancel := context.WithTimeout(stream.Context(), awsTimeout)
	defer cancel()

	instancesDesc, err := awsClient.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(attestationData.InstanceID)},
		Filters:     instanceFilters,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to describe instance: %v", err)
	}

	// Ideally we wouldn't do this work at all if the agent has already attested
	// e.g. do it after the call to `p.IsAttested`, however, we may need
	// the instance to construct tags used in the agent ID.
	//
	// This overhead will only effect agents attempting to re-attest which
	// should be a very small portion of the overall server workload. This
	// is a potential DoS vector.
	shouldCheckBlockDevice := !inTrustAcctList && !c.SkipBlockDevice
	var instance *ec2.Instance
	var tags = make(instanceTags)
	if strings.Contains(c.AgentPathTemplate, ".Tags") || shouldCheckBlockDevice {
		var err error
		instance, err = p.getEC2Instance(instancesDesc)
		if err != nil {
			return err
		}

		tags = tagsFromInstance(instance)
	}

	if shouldCheckBlockDevice {
		if err = p.checkBlockDevice(instance); err != nil {
			return status.Errorf(codes.Internal, "failed aws ec2 attestation: %v", err)
		}
	}

	agentID, err := makeAgentID(c.trustDomain, c.pathTemplate, attestationData, tags)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create spiffe ID: %v", err)
	}

	attested, err := p.IsAttested(stream.Context(), agentID.String())
	switch {
	case err != nil:
		return err
	case attested:
		return status.Error(codes.PermissionDenied, "IID has already been used to attest an agent")
	}

	selectorValues, err := p.resolveSelectors(stream.Context(), instancesDesc, awsClient)
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    false,
				SpiffeId:       agentID.String(),
				SelectorValues: selectorValues,
			},
		},
	})
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(IIDAttestorConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// Get the AWS CA public key. We do this lazily on configure so deployments
	// not using this plugin don't pay for parsing it on startup. This
	// operation should not fail, but we check the return value just in case.
	awsCAPublicKey, err := p.hooks.getAWSCAPublicKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load the AWS CA public key: %v", err)
	}
	config.awsCAPublicKey = awsCAPublicKey

	if err := config.Validate(p.hooks.getenv(accessKeyIDVarName), p.hooks.getenv(secretAccessKeyVarName)); err != nil {
		return nil, err
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}
	config.trustDomain, err = spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "core configuration has invalid trust domain: %v", err)
	}

	config.pathTemplate = defaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		config.pathTemplate = tmpl
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config
	p.clients.configure(config.SessionConfig)

	return &configv1.ConfigureResponse{}, nil
}

// SetLogger sets this plugin's logger
func (p *IIDAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *IIDAttestorPlugin) checkBlockDevice(instance *ec2.Instance) error {
	ifaceZeroDeviceIndex := *instance.NetworkInterfaces[0].Attachment.DeviceIndex

	if ifaceZeroDeviceIndex != 0 {
		return fmt.Errorf("the EC2 instance network interface attachment device index must be zero (has %d)", ifaceZeroDeviceIndex)
	}

	ifaceZeroAttachTime := instance.NetworkInterfaces[0].Attachment.AttachTime

	// skip anti-tampering mechanism when RootDeviceType is instance-store
	// specifically, if device type is persistent, and the device was attached past
	// a threshold time after instance boot, fail attestation
	if *instance.RootDeviceType != ec2.DeviceTypeInstanceStore {
		rootDeviceIndex := -1
		for i, bdm := range instance.BlockDeviceMappings {
			if *bdm.DeviceName == *instance.RootDeviceName {
				rootDeviceIndex = i
				break
			}
		}

		if rootDeviceIndex == -1 {
			return fmt.Errorf("failed to locate the root device block mapping with name %q", *instance.RootDeviceName)
		}

		rootDeviceAttachTime := instance.BlockDeviceMappings[rootDeviceIndex].Ebs.AttachTime

		attachTimeDisparitySeconds := int64(math.Abs(float64(ifaceZeroAttachTime.Unix() - rootDeviceAttachTime.Unix())))

		if attachTimeDisparitySeconds > maxSecondsBetweenDeviceAttachments {
			return fmt.Errorf("failed checking the disparity device attach times, root BlockDeviceMapping and NetworkInterface[0] attach times differ by %d seconds", attachTimeDisparitySeconds)
		}
	}

	return nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *IIDAttestorPlugin) getEC2Instance(instancesDesc *ec2.DescribeInstancesOutput) (*ec2.Instance, error) {
	if len(instancesDesc.Reservations) < 1 {
		return nil, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no reservations")
	}

	if len(instancesDesc.Reservations[0].Instances) < 1 {
		return nil, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no instances")
	}

	return instancesDesc.Reservations[0].Instances[0], nil
}

func tagsFromInstance(instance *ec2.Instance) instanceTags {
	tags := make(instanceTags, len(instance.Tags))
	for _, tag := range instance.Tags {
		if tag != nil && tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags
}

func unmarshalAndValidateIdentityDocument(data []byte, pubKey *rsa.PublicKey) (ec2metadata.EC2InstanceIdentityDocument, error) {
	var attestationData caws.IIDAttestationData
	if err := json.Unmarshal(data, &attestationData); err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed to unmarshal the attestation data: %v", err)
	}

	var doc ec2metadata.EC2InstanceIdentityDocument
	if err := json.Unmarshal([]byte(attestationData.Document), &doc); err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed to unmarshal the IID: %v", err)
	}

	docHash := sha256.Sum256([]byte(attestationData.Document))

	sigBytes, err := base64.StdEncoding.DecodeString(attestationData.Signature)
	if err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed to decode the IID signature: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes); err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed to verify the cryptographic signature: %v", err)
	}

	return doc, nil
}

func (p *IIDAttestorPlugin) resolveSelectors(parent context.Context, instancesDesc *ec2.DescribeInstancesOutput, client Client) ([]string, error) {
	selectorSet := map[string]bool{}
	addSelectors := func(values []string) {
		for _, value := range values {
			selectorSet[value] = true
		}
	}
	c, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	for _, reservation := range instancesDesc.Reservations {
		for _, instance := range reservation.Instances {
			addSelectors(resolveTags(instance.Tags))
			addSelectors(resolveSecurityGroups(instance.SecurityGroups))
			if !c.DisableInstanceProfileSelectors && instance.IamInstanceProfile != nil && instance.IamInstanceProfile.Arn != nil {
				instanceProfileName, err := instanceProfileNameFromArn(*instance.IamInstanceProfile.Arn)
				if err != nil {
					return nil, err
				}
				ctx, cancel := context.WithTimeout(parent, awsTimeout)
				defer cancel()
				output, err := client.GetInstanceProfileWithContext(ctx, &iam.GetInstanceProfileInput{
					InstanceProfileName: aws.String(instanceProfileName),
				})
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to get intance profile: %v", err)
				}
				addSelectors(resolveInstanceProfile(output.InstanceProfile))
			}
		}
	}

	// build and sort selectors
	selectors := []string{}
	for value := range selectorSet {
		selectors = append(selectors, value)
	}
	sort.Strings(selectors)

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
		return "", status.Errorf(codes.Internal, "failed to parse %v", err)
	}
	m := reInstanceProfileARNResource.FindStringSubmatch(a.Resource)
	if m == nil {
		return "", status.Errorf(codes.Internal, "arn is not for an instance profile")
	}

	name := strings.Split(m[1], "/")
	// only the last element is the profile name
	return name[len(name)-1], nil
}
