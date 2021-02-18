package aws

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

var (
	iidError        = caws.IidErrorClass
	_awsTimeout     = 5 * time.Second
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

const awsCaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`

// BuiltIn creates a new built-in plugin
func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(caws.PluginName,
		nodeattestor.PluginServer(p),
	)
}

// IIDAttestorPlugin implements node attestation for agents running in aws.
type IIDAttestorPlugin struct {
	nodeattestorbase.Base

	config  *IIDAttestorConfig
	mtx     sync.RWMutex
	clients *clientsCache

	hooks struct {
		// in test, this can be overridden to mock OS env
		getenv func(string) string
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
	pathTemplate                    *template.Template
	trustDomain                     string
	awsCaCertPublicKey              *rsa.PublicKey
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	p := &IIDAttestorPlugin{}
	p.clients = newClientsCache(defaultNewClientCallback)
	p.hooks.getenv = os.Getenv
	return p
}

// Attest implements the server side logic for the aws iid node attestation plugin.
func (p *IIDAttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	genAttestData := req.GetAttestationData()
	if genAttestData == nil {
		return iidError.New("request missing attestation data")
	}

	if genAttestData.Type != caws.PluginName {
		return iidError.New("unexpected attestation data type %q", genAttestData.Type)
	}

	validDoc, err := unmarshalAndValidateIdentityDocument(genAttestData.Data, c.awsCaCertPublicKey)
	if err != nil {
		return err
	}

	inTrustAcctList := false
	for _, id := range c.LocalValidAcctIDs {
		if validDoc.AccountID == id {
			inTrustAcctList = true
			break
		}
	}

	awsClient, err := p.clients.getClient(validDoc.Region)
	if err != nil {
		return iidError.New("failed to get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(stream.Context(), _awsTimeout)
	defer cancel()

	instancesDesc, err := awsClient.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(validDoc.InstanceID)},
		Filters:     instanceFilters,
	})
	if err != nil {
		return caws.AttestationStepError("querying AWS via describe-instances", err)
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
		err = p.checkBlockDevice(instance)
		if err != nil {
			return iidError.New("failed aws ec2 attestation: %w", err)
		}
	}

	agentID, err := makeSpiffeID(c.trustDomain, c.pathTemplate, validDoc, tags)
	if err != nil {
		return iidError.New("failed to create spiffe ID: %w", err)
	}

	attested, err := p.IsAttested(stream.Context(), agentID.String())
	switch {
	case err != nil:
		return err
	case attested:
		return iidError.New("IID has already been used to attest an agent")
	}

	selectors, err := p.resolveSelectors(stream.Context(), instancesDesc, awsClient)
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   agentID.String(),
		Selectors: selectors.Entries,
	})
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := iidError.New("error parsing AWS IID Attestor configuration: %w", err)
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := iidError.New("error decoding AWS IID Attestor configuration: %w", err)
		return resp, err
	}

	block, _ := pem.Decode([]byte(awsCaCertPEM))

	awsCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err := iidError.New("error reading the AWS CA Certificate in the AWS IID Attestor: %w", err)
		return resp, err
	}

	awsCaCertPublicKey, ok := awsCaCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err := iidError.New("error extracting the AWS CA Certificate's public key in the AWS IID Attestor: %w", err)
		return resp, err
	}
	config.awsCaCertPublicKey = awsCaCertPublicKey

	if err := config.Validate(p.hooks.getenv(accessKeyIDVarName), p.hooks.getenv(secretAccessKeyVarName)); err != nil {
		return nil, err
	}

	if req.GlobalConfig == nil {
		return resp, iidError.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return resp, iidError.New("trust_domain is required")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	config.pathTemplate = defaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, iidError.New("failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		config.pathTemplate = tmpl
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config
	p.clients.configure(config.SessionConfig)

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and related metadata of the installed plugin.
func (*IIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// SetLogger sets this plugin's logger
func (p *IIDAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *IIDAttestorPlugin) checkBlockDevice(instance *ec2.Instance) error {
	ifaceZeroDeviceIndex := *instance.NetworkInterfaces[0].Attachment.DeviceIndex

	if ifaceZeroDeviceIndex != 0 {
		innerErr := iidError.New("the DeviceIndex is %d", ifaceZeroDeviceIndex)
		return caws.AttestationStepError("verifying the EC2 instance's NetworkInterface[0].DeviceIndex is 0", innerErr)
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
			innerErr := iidError.New("could not locate a device mapping with name '%v'", instance.RootDeviceName)
			return caws.AttestationStepError("locating the root device block mapping", innerErr)
		}

		rootDeviceAttachTime := instance.BlockDeviceMappings[rootDeviceIndex].Ebs.AttachTime

		attachTimeDisparitySeconds := int64(math.Abs(float64(ifaceZeroAttachTime.Unix() - rootDeviceAttachTime.Unix())))

		if attachTimeDisparitySeconds > maxSecondsBetweenDeviceAttachments {
			innerErr := iidError.New("root BlockDeviceMapping and NetworkInterface[0] attach times differ by %d seconds", attachTimeDisparitySeconds)
			return caws.AttestationStepError("checking the disparity device attach times", innerErr)
		}
	}

	return nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, iidError.New("not configured")
	}

	return p.config, nil
}

func (p *IIDAttestorPlugin) getEC2Instance(instancesDesc *ec2.DescribeInstancesOutput) (*ec2.Instance, error) {
	if len(instancesDesc.Reservations) < 1 {
		return nil, caws.AttestationStepError("querying AWS via describe-instances", iidError.New("returned no reservations"))
	}

	if len(instancesDesc.Reservations[0].Instances) < 1 {
		return nil, caws.AttestationStepError("querying AWS via describe-instances", iidError.New("returned no instances"))
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
		return ec2metadata.EC2InstanceIdentityDocument{}, caws.AttestationStepError("unmarshaling the attestation data", err)
	}

	var doc ec2metadata.EC2InstanceIdentityDocument
	if err := json.Unmarshal([]byte(attestationData.Document), &doc); err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, caws.AttestationStepError("unmarshaling the IID", err)
	}

	docHash := sha256.Sum256([]byte(attestationData.Document))

	sigBytes, err := base64.StdEncoding.DecodeString(attestationData.Signature)
	if err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, caws.AttestationStepError("base64 decoding the IID signature", err)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes); err != nil {
		return ec2metadata.EC2InstanceIdentityDocument{}, caws.AttestationStepError("verifying the cryptographic signature", err)
	}

	return doc, nil
}

func (p *IIDAttestorPlugin) resolveSelectors(parent context.Context, instancesDesc *ec2.DescribeInstancesOutput, client Client) (*common.Selectors, error) {
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
				ctx, cancel := context.WithTimeout(parent, _awsTimeout)
				defer cancel()
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
			Type:  caws.PluginName,
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
