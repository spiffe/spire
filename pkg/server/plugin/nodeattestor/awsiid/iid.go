package awsiid

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/fullsailor/pkcs7"
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
	instanceFilters = []ec2types.Filter{
		{
			Name: aws.String("instance-state-name"),
			Values: []string{
				"pending",
				"running",
			},
		},
	}

	defaultPartition = "aws"
	// No constant was found in the sdk, using the list of paritions defined on
	// the page https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
	partitions = []string{
		defaultPartition,
		"aws-cn",
		"aws-us-gov",
	}
)

const (
	maxSecondsBetweenDeviceAttachments int64 = 60
	// accessKeyIDVarName env var name for AWS access key ID
	accessKeyIDVarName = "AWS_ACCESS_KEY_ID"
	// secretAccessKeyVarName env car name for AWS secret access key
	secretAccessKeyVarName   = "AWS_SECRET_ACCESS_KEY" //nolint: gosec // false positive
	azSelectorPrefix         = "az"
	imageIDSelectorPrefix    = "image:id"
	instanceIDSelectorPrefix = "instance:id"
	regionSelectorPrefix     = "region"
	sgIDSelectorPrefix       = "sg:id"
	sgNameSelectorPrefix     = "sg:name"
	tagSelectorPrefix        = "tag"
	iamRoleSelectorPrefix    = "iamrole"
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
		getAWSCACertificate func(string, PublicKeyType) (*x509.Certificate, error)
		getenv              func(string) string
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
	Partition                       string   `hcl:"partition"`
	pathTemplate                    *agentpathtemplate.Template
	trustDomain                     spiffeid.TrustDomain
	getAWSCACertificate             func(string, PublicKeyType) (*x509.Certificate, error)
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	p := &IIDAttestorPlugin{}
	p.clients = newClientsCache(defaultNewClientCallback)
	p.hooks.getAWSCACertificate = getAWSCACertificate
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

	attestationData, err := unmarshalAndValidateIdentityDocument(payload, c.getAWSCACertificate)
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

	ctx, cancel := context.WithTimeout(stream.Context(), awsTimeout)
	defer cancel()

	awsClient, err := p.clients.getClient(ctx, attestationData.Region, attestationData.AccountID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get client: %v", err)
	}

	instancesDesc, err := awsClient.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{attestationData.InstanceID},
		Filters:     instanceFilters,
	})

	if err != nil {
		return status.Errorf(codes.Internal, "failed to describe instance: %v", err)
	}

	// Ideally we wouldn't do this work at all if the agent has already attested
	// e.g. do it after the call to `p.AssessTOFU`, however, we may need
	// the instance to construct tags used in the agent ID.
	//
	// This overhead will only effect agents attempting to re-attest which
	// should be a very small portion of the overall server workload. This
	// is a potential DoS vector.
	shouldCheckBlockDevice := !inTrustAcctList && !c.SkipBlockDevice
	var instance ec2types.Instance
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

	if err := p.AssessTOFU(stream.Context(), agentID.String(), p.log); err != nil {
		return err
	}

	selectorValues, err := p.resolveSelectors(stream.Context(), instancesDesc, attestationData, awsClient)
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
func (p *IIDAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(IIDAttestorConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// Function to get the AWS CA certificate. We do this lazily on configure so deployments
	// not using this plugin don't pay for parsing it on startup. This
	// operation should not fail, but we check the return value just in case.
	config.getAWSCACertificate = p.hooks.getAWSCACertificate

	if err := config.Validate(p.hooks.getenv(accessKeyIDVarName), p.hooks.getenv(secretAccessKeyVarName)); err != nil {
		return nil, err
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	var err error
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

	if config.Partition == "" {
		config.Partition = defaultPartition
	}
	if !isValidAWSPartition(config.Partition) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid partition %q, must be one of: %v", config.Partition, partitions)
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

func (p *IIDAttestorPlugin) checkBlockDevice(instance ec2types.Instance) error {
	ifaceZeroDeviceIndex := *instance.NetworkInterfaces[0].Attachment.DeviceIndex

	if ifaceZeroDeviceIndex != 0 {
		return fmt.Errorf("the EC2 instance network interface attachment device index must be zero (has %d)", ifaceZeroDeviceIndex)
	}

	ifaceZeroAttachTime := instance.NetworkInterfaces[0].Attachment.AttachTime

	// skip anti-tampering mechanism when RootDeviceType is instance-store
	// specifically, if device type is persistent, and the device was attached past
	// a threshold time after instance boot, fail attestation
	if instance.RootDeviceType != ec2types.DeviceTypeInstanceStore {
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

func (p *IIDAttestorPlugin) getEC2Instance(instancesDesc *ec2.DescribeInstancesOutput) (ec2types.Instance, error) {
	if len(instancesDesc.Reservations) < 1 {
		return ec2types.Instance{}, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no reservations")
	}

	if len(instancesDesc.Reservations[0].Instances) < 1 {
		return ec2types.Instance{}, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no instances")
	}

	return instancesDesc.Reservations[0].Instances[0], nil
}

func tagsFromInstance(instance ec2types.Instance) instanceTags {
	tags := make(instanceTags, len(instance.Tags))
	for _, tag := range instance.Tags {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags
}

func unmarshalAndValidateIdentityDocument(data []byte, getAWSCACertificate func(string, PublicKeyType) (*x509.Certificate, error)) (imds.InstanceIdentityDocument, error) {
	var attestationData caws.IIDAttestationData
	if err := json.Unmarshal(data, &attestationData); err != nil {
		return imds.InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed to unmarshal the attestation data: %v", err)
	}

	var doc imds.InstanceIdentityDocument
	if err := json.Unmarshal([]byte(attestationData.Document), &doc); err != nil {
		return imds.InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed to unmarshal the IID: %v", err)
	}

	var signature string
	var publicKeyType PublicKeyType

	// Use the RSA-2048 signature if present, otherwise use the RSA-1024 signature
	// This enables the support of new and old SPIRE agents, maintaining backwards compatibility.
	if attestationData.SignatureRSA2048 != "" {
		signature = attestationData.SignatureRSA2048
		publicKeyType = RSA2048
	} else {
		signature = attestationData.Signature
		publicKeyType = RSA1024
	}

	if signature == "" {
		return imds.InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "instance identity cryptographic signature is required")
	}

	caCert, err := getAWSCACertificate(doc.Region, publicKeyType)
	if err != nil {
		return imds.InstanceIdentityDocument{}, status.Errorf(codes.Internal, "failed to load the AWS CA certificate for region %q: %v", doc.Region, err)
	}

	switch publicKeyType {
	case RSA1024:
		if err := verifyRSASignature(caCert.PublicKey.(*rsa.PublicKey), attestationData.Document, signature); err != nil {
			return imds.InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, err.Error())
		}
	case RSA2048:
		pkcs7Sig, err := decodeAndParsePKCS7Signature(signature, caCert)
		if err != nil {
			return imds.InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, err.Error())
		}

		if err := pkcs7Sig.Verify(); err != nil {
			return imds.InstanceIdentityDocument{}, status.Errorf(codes.InvalidArgument, "failed verification of instance identity cryptographic signature: %v", err)
		}
	}

	return doc, nil
}

func verifyRSASignature(pubKey *rsa.PublicKey, doc string, signature string) error {
	docHash := sha256.Sum256([]byte(doc))

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to decode the IID signature: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to verify the cryptographic signature: %v", err)
	}

	return nil
}

func decodeAndParsePKCS7Signature(signature string, caCert *x509.Certificate) (*pkcs7.PKCS7, error) {
	signaturePEM := addPKCS7HeaderAndFooter(signature)
	signatureBlock, _ := pem.Decode([]byte(signaturePEM))
	if signatureBlock == nil {
		return nil, errors.New("failed to decode the instance identity cryptographic signature")
	}

	pkcs7Sig, err := pkcs7.Parse(signatureBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the instance identity cryptographic signature: %w", err)
	}

	// add the CA certificate to the PKCS7 signature to verify it
	pkcs7Sig.Certificates = []*x509.Certificate{caCert}
	return pkcs7Sig, nil
}

// AWS returns the PKCS7 signature without the header and footer. This function adds them to be able to parse
// the signature as a PEM block.
func addPKCS7HeaderAndFooter(signature string) string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN PKCS7-----\n")
	sb.WriteString(signature)
	sb.WriteString("\n-----END PKCS7-----\n")
	return sb.String()
}

func (p *IIDAttestorPlugin) resolveSelectors(parent context.Context, instancesDesc *ec2.DescribeInstancesOutput, iiDoc imds.InstanceIdentityDocument, client Client) ([]string, error) {
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
				output, err := client.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
					InstanceProfileName: aws.String(instanceProfileName),
				})
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to get intance profile: %v", err)
				}
				addSelectors(resolveInstanceProfile(output.InstanceProfile))
			}
		}
	}

	resolveIIDocSelectors(selectorSet, iiDoc)

	// build and sort selectors
	selectors := []string{}
	for value := range selectorSet {
		selectors = append(selectors, value)
	}
	sort.Strings(selectors)

	return selectors, nil
}

func resolveIIDocSelectors(selectorSet map[string]bool, iiDoc imds.InstanceIdentityDocument) {
	selectorSet[fmt.Sprintf("%s:%s", imageIDSelectorPrefix, iiDoc.ImageID)] = true
	selectorSet[fmt.Sprintf("%s:%s", instanceIDSelectorPrefix, iiDoc.InstanceID)] = true
	selectorSet[fmt.Sprintf("%s:%s", regionSelectorPrefix, iiDoc.Region)] = true
	selectorSet[fmt.Sprintf("%s:%s", azSelectorPrefix, iiDoc.AvailabilityZone)] = true
}

func resolveTags(tags []ec2types.Tag) []string {
	values := make([]string, 0, len(tags))
	for _, tag := range tags {
		values = append(values, fmt.Sprintf("%s:%s:%s", tagSelectorPrefix, aws.ToString(tag.Key), aws.ToString(tag.Value)))
	}
	return values
}

func resolveSecurityGroups(sgs []ec2types.GroupIdentifier) []string {
	values := make([]string, 0, len(sgs)*2)
	for _, sg := range sgs {
		values = append(values,
			fmt.Sprintf("%s:%s", sgIDSelectorPrefix, aws.ToString(sg.GroupId)),
			fmt.Sprintf("%s:%s", sgNameSelectorPrefix, aws.ToString(sg.GroupName)),
		)
	}
	return values
}

func resolveInstanceProfile(instanceProfile *iamtypes.InstanceProfile) []string {
	if instanceProfile == nil {
		return nil
	}
	values := make([]string, 0, len(instanceProfile.Roles))
	for _, role := range instanceProfile.Roles {
		if role.Arn != nil {
			values = append(values, fmt.Sprintf("%s:%s", iamRoleSelectorPrefix, aws.ToString(role.Arn)))
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

func isValidAWSPartition(partition string) bool {
	for _, p := range partitions {
		if p == partition {
			return true
		}
	}
	return false
}
