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
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"

	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

var _awsTimeout = 5 * time.Second

const (
	maxSecondsBetweenDeviceAttachments int64 = 60
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
	config *IIDAttestorConfig
	mtx    sync.RWMutex
	hooks  struct {
		// in test, this can be overridden to get mock client
		getClient func(p client.ConfigProvider, cfgs ...*aws.Config) EC2Client
		// in test, this can be overridden to mock OS env
		getEnv func(string) string
	}
	log hclog.Logger
}

// IIDAttestorConfig holds hcl configuration for IID attestor plugin
type IIDAttestorConfig struct {
	caws.SessionConfig `hcl:",squash"`
	SkipBlockDevice    bool     `hcl:"skip_block_device"`
	LocalValidAcctIDs  []string `hcl:"account_ids_for_local_validation"`
	AgentPathTemplate  string   `hcl:"agent_path_template"`
	pathTemplate       *template.Template
	trustDomain        string
	awsCaCertPublicKey *rsa.PublicKey
}

// New creates a new IITAttestorPlugin.
func New() *IIDAttestorPlugin {
	p := &IIDAttestorPlugin{}
	p.hooks.getClient = func(p client.ConfigProvider, cfgs ...*aws.Config) EC2Client {
		return ec2.New(p, cfgs...)
	}
	p.hooks.getEnv = os.Getenv
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
		return errors.New("request missing attestation data")
	}

	if genAttestData.Type != caws.PluginName {
		return fmt.Errorf("unexpected attestation data type %q", genAttestData.Type)
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

	// Ideally we wouldn't do this work at all if the agent has already attested
	// e.g. do it after the call to `p.IsAttested`, however, we may need
	// the instance to construct tags used in the agent ID.
	//
	// This overhead will only effect agents attempting to re-attest which
	// should be a very small portion of the overall server workload. This
	// is a potential DoS vector.
	shouldCheckBlockDevice := !inTrustAcctList && !c.SkipBlockDevice
	var instance *ec2.Instance
	if strings.Contains(c.AgentPathTemplate, ".Tags") || shouldCheckBlockDevice {
		var err error
		instance, err = p.getEC2Instance(stream.Context(), c, validDoc)
		if err != nil {
			return err
		}
	}

	if shouldCheckBlockDevice {
		err = p.checkBlockDevice(instance)
		if err != nil {
			return fmt.Errorf("failed aws ec2 attestation: %v", err)
		}
	}

	tags := tagsFromInstance(instance)

	agentID, err := makeSpiffeID(c.trustDomain, c.pathTemplate, validDoc, tags)
	if err != nil {
		return fmt.Errorf("failed to create spiffe ID: %v", err)
	}

	attested, err := p.IsAttested(stream.Context(), agentID.String())
	switch {
	case err != nil:
		return err
	case attested:
		return errors.New("IID has already been used to attest an agent")
	}

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId: agentID.String(),
	})
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := fmt.Errorf("error parsing AWS IID Attestor configuration: %s", err)
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := fmt.Errorf("error decoding AWS IID Attestor configuration: %v", err)
		return resp, err
	}

	block, _ := pem.Decode([]byte(awsCaCertPEM))

	awsCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err := fmt.Errorf("error reading the AWS CA Certificate in the AWS IID Attestor: %v", err)
		return resp, err
	}

	awsCaCertPublicKey, ok := awsCaCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err := fmt.Errorf("error extracting the AWS CA Certificate's public key in the AWS IID Attestor: %v", err)
		return resp, err
	}
	config.awsCaCertPublicKey = awsCaCertPublicKey

	if config.AccessKeyID == "" {
		config.AccessKeyID = p.hooks.getEnv(caws.AccessKeyIDVarName)
	}

	if config.SecretAccessKey == "" {
		config.SecretAccessKey = p.hooks.getEnv(caws.SecretAccessKeyVarName)
	}

	switch {
	case config.AccessKeyID != "" && config.SecretAccessKey == "":
		return nil, errors.New("configuration missing secret access key, but has access key id")
	case config.AccessKeyID == "" && config.SecretAccessKey != "":
		return nil, errors.New("configuration missing access key id, but has secret access key")
	}

	if req.GlobalConfig == nil {
		err := fmt.Errorf("global configuration is required")
		return resp, err
	}
	if req.GlobalConfig.TrustDomain == "" {
		err := fmt.Errorf("trust_domain is required")
		return resp, err
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	config.pathTemplate = defaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		config.pathTemplate = tmpl
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

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
		innerErr := fmt.Errorf("the DeviceIndex is %d", ifaceZeroDeviceIndex)
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
			innerErr := fmt.Errorf("could not locate a device mapping with name '%v'", instance.RootDeviceName)
			return caws.AttestationStepError("locating the root device block mapping", innerErr)
		}

		rootDeviceAttachTime := instance.BlockDeviceMappings[rootDeviceIndex].Ebs.AttachTime

		attachTimeDisparitySeconds := int64(math.Abs(float64(ifaceZeroAttachTime.Unix() - rootDeviceAttachTime.Unix())))

		if attachTimeDisparitySeconds > maxSecondsBetweenDeviceAttachments {
			innerErr := fmt.Errorf("root BlockDeviceMapping and NetworkInterface[0] attach times differ by %d seconds", attachTimeDisparitySeconds)
			return caws.AttestationStepError("checking the disparity device attach times", innerErr)
		}
	}

	return nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, errors.New("not configured")
	}
	return p.config, nil
}

func (p *IIDAttestorPlugin) getEC2Instance(ctx context.Context, c *IIDAttestorConfig, doc caws.InstanceIdentityDocument) (*ec2.Instance, error) {
	awsSession, err := caws.NewAWSSession(c.AccessKeyID, c.SecretAccessKey, doc.Region)
	if err != nil {
		return nil, caws.AttestationStepError("creating AWS session", err)
	}

	ec2Client := p.hooks.getClient(awsSession)

	query := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{&doc.InstanceID},
	}

	ctx, cancel := context.WithTimeout(ctx, _awsTimeout)
	defer cancel()

	result, err := ec2Client.DescribeInstancesWithContext(ctx, query)
	if err != nil {
		return nil, caws.AttestationStepError("querying AWS via describe-instances", err)
	}

	if len(result.Reservations) < 1 {
		return nil, caws.AttestationStepError("querying AWS via describe-instances", errors.New("returned no reservations"))
	}

	if len(result.Reservations[0].Instances) < 1 {
		return nil, caws.AttestationStepError("querying AWS via describe-instances", errors.New("returned no instances"))
	}

	return result.Reservations[0].Instances[0], nil
}

func tagsFromInstance(instance *ec2.Instance) instanceTags {
	if instance == nil {
		return make(instanceTags)
	}

	tags := make(instanceTags, len(instance.Tags))
	for _, tag := range instance.Tags {
		if tag != nil && tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags
}

func unmarshalAndValidateIdentityDocument(data []byte, pubKey *rsa.PublicKey) (caws.InstanceIdentityDocument, error) {
	var attestationData caws.IIDAttestationData
	if err := json.Unmarshal(data, &attestationData); err != nil {
		return caws.InstanceIdentityDocument{}, caws.AttestationStepError("unmarshaling the attestation data", err)
	}

	var doc caws.InstanceIdentityDocument
	if err := json.Unmarshal([]byte(attestationData.Document), &doc); err != nil {
		return caws.InstanceIdentityDocument{}, caws.AttestationStepError("unmarshaling the IID", err)
	}

	docHash := sha256.Sum256([]byte(attestationData.Document))

	sigBytes, err := base64.StdEncoding.DecodeString(attestationData.Signature)
	if err != nil {
		return caws.InstanceIdentityDocument{}, caws.AttestationStepError("base64 decoding the IID signature", err)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes); err != nil {
		return caws.InstanceIdentityDocument{}, caws.AttestationStepError("verifying the cryptographic signature", err)
	}

	return doc, nil
}
