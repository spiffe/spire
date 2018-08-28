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
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/server/nodeattestor"

	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	pluginName = "aws_iid"

	accessKeyIDVarName     = "AWS_ACCESS_KEY_ID"
	secretAccessKeyVarName = "AWS_SECRET_ACCESS_KEY"

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

type IIDAttestorConfig struct {
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
	SkipBlockDevice bool   `hcl:"skip_block_device"`
}

type IIDAttestorPlugin struct {
	trustDomain string

	awsCaCertPublicKey *rsa.PublicKey
	accessKeyId        string
	secretAccessKey    string
	skipBlockDevice    bool
	mtx                *sync.Mutex
}

func (p *IIDAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	var attestationData caws.IIDAttestationData
	err = json.Unmarshal(req.AttestationData.Data, &attestationData)
	if err != nil {
		return caws.AttestationStepError("unmarshaling the attestation data", err)
	}

	var doc caws.InstanceIdentityDocument
	err = json.Unmarshal([]byte(attestationData.Document), &doc)
	if err != nil {
		return caws.AttestationStepError("unmarshaling the IID", err)
	}

	if req.AttestedBefore {
		return caws.AttestationStepError("validating the IID", fmt.Errorf("the IID has been used and is no longer valid"))
	}

	docHash := sha256.Sum256([]byte(attestationData.Document))

	sigBytes, err := base64.StdEncoding.DecodeString(attestationData.Signature)
	if err != nil {
		return caws.AttestationStepError("base64 decoding the IID signature", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	err = rsa.VerifyPKCS1v15(p.awsCaCertPublicKey, crypto.SHA256, docHash[:], sigBytes)
	if err != nil {
		return caws.AttestationStepError("verifying the cryptographic signature", err)
	}

	var awsSession *session.Session

	if p.secretAccessKey != "" && p.accessKeyId != "" {
		creds := credentials.NewStaticCredentials(p.accessKeyId, p.secretAccessKey, "")
		awsSession = session.Must(session.NewSession(&aws.Config{Credentials: creds, Region: &doc.Region}))
	} else {
		awsSession = session.Must(session.NewSession(&aws.Config{Region: &doc.Region}))
	}

	ec2Client := ec2.New(awsSession)

	query := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{&doc.InstanceId},
	}

	result, err := ec2Client.DescribeInstances(query)
	if err != nil {
		return caws.AttestationStepError("querying AWS via describe-instances", err)
	}

	instance := result.Reservations[0].Instances[0]

	ifaceZeroDeviceIndex := *instance.NetworkInterfaces[0].Attachment.DeviceIndex

	if ifaceZeroDeviceIndex != 0 {
		innerErr := fmt.Errorf("DeviceIndex is %d", ifaceZeroDeviceIndex)
		return caws.AttestationStepError("verifying the EC2 instance's NetworkInterface[0].DeviceIndex is 0", innerErr)
	}

	ifaceZeroAttachTime := instance.NetworkInterfaces[0].Attachment.AttachTime

	// skip anti-tampering mechanism when RootDeviceType is instance-store
	if *instance.RootDeviceType != ec2.DeviceTypeInstanceStore && p.skipBlockDevice != true {
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

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: caws.IIDAgentID(p.trustDomain, doc.AccountId, doc.Region, doc.InstanceId),
	}

	return stream.Send(resp)
}

func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := fmt.Errorf("Error parsing AWS IID Attestor configuration: %s", err)
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := fmt.Errorf("Error decoding AWS IID Attestor configuration: %v", err)
		return resp, err
	}

	block, _ := pem.Decode([]byte(awsCaCertPEM))

	awsCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err := fmt.Errorf("Error reading the AWS CA Certificate in the AWS IID Attestor: %v", err)
		return resp, err
	}

	awsCaCertPublicKey, ok := awsCaCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err := fmt.Errorf("Error extracting the AWS CA Certificate's public key in the AWS IID Attestor: %v", err)
		return resp, err
	}

	if config.AccessKeyID == "" {
		config.AccessKeyID = os.Getenv(accessKeyIDVarName)
	}

	if config.SecretAccessKey == "" {
		config.SecretAccessKey = os.Getenv(secretAccessKeyVarName)
	}

	if req.GlobalConfig == nil {
		err := fmt.Errorf("global configuration is required")
		return resp, err
	}
	if req.GlobalConfig.TrustDomain == "" {
		err := fmt.Errorf("trust_domain is required")
		return resp, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.trustDomain = req.GlobalConfig.TrustDomain
	p.awsCaCertPublicKey = awsCaCertPublicKey
	p.accessKeyId = config.AccessKeyID
	p.secretAccessKey = config.SecretAccessKey
	p.skipBlockDevice = config.SkipBlockDevice

	return &spi.ConfigureResponse{}, nil
}

func (*IIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewIID() nodeattestor.Plugin {
	return &IIDAttestorPlugin{
		mtx: &sync.Mutex{},
	}
}
