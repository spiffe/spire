package awsiid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/fullsailor/pkcs7"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testInstanceProfileArn         = "arn:aws:iam::123412341234:instance-profile/nodes.test.k8s.local"
	testInstanceProfileWithPathArn = "arn:aws:iam::123412341234:instance-profile/some/path/nodes.test.k8s.local"
	testInstanceProfileName        = "nodes.test.k8s.local"
)

var (
	testAWSCAKey         = testkey.MustRSA2048()
	testInstance         = "test-instance"
	testAccount          = "test-account"
	testRegion           = "test-region"
	testAvailabilityZone = "test-az"
	testImageID          = "test-image-id"
	testProfile          = "test-profile"
	zeroDeviceIndex      = int32(0)
	nonzeroDeviceIndex   = int32(1)
	instanceStoreType    = ec2types.DeviceTypeInstanceStore
	ebsType              = ec2types.DeviceTypeEbs
	testAWSCACert        *x509.Certificate
	otherAWSCACert       *x509.Certificate
)

func TestAttest(t *testing.T) {
	testAWSCACert = generateCertificate(t, testAWSCAKey)
	otherAWSCACert = generateCertificate(t, testkey.MustRSA2048())
	defaultAttestationData := buildAttestationDataRSA2048Signature(t)
	attentionDataWithRSA1024Signature := buildAttestationDataRSA1024Signature(t)

	for _, tt := range []struct {
		name                           string
		env                            map[string]string
		skipConfigure                  bool
		config                         string
		alreadyAttested                bool
		mutateDescribeInstancesOutput  func(output *ec2.DescribeInstancesOutput)
		describeInstancesError         error
		mutateGetInstanceProfileOutput func(output *iam.GetInstanceProfileOutput)
		getInstanceProfileError        error
		overrideAttestationData        func(caws.IIDAttestationData) caws.IIDAttestationData
		overridePayload                func() []byte
		expectCode                     codes.Code
		expectMsgPrefix                string
		expectID                       string
		expectSelectors                []*common.Selector
		overrideCACert                 *x509.Certificate
	}{
		{
			name:            "plugin not configured",
			skipConfigure:   true,
			expectCode:      codes.FailedPrecondition,
			expectMsgPrefix: "nodeattestor(aws_iid): not configured",
		},
		{
			name:            "missing payload",
			overridePayload: func() []byte { return nil },
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "payload cannot be empty",
		},
		{
			name:            "malformed payload",
			overridePayload: func() []byte { return []byte("malformed payload") },
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "nodeattestor(aws_iid): failed to unmarshal the attestation data:",
		},
		{
			name: "missing signature",
			overrideAttestationData: func(data caws.IIDAttestationData) caws.IIDAttestationData {
				data.SignatureRSA2048 = ""
				data.Signature = ""
				return data
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "nodeattestor(aws_iid): instance identity cryptographic signature is required",
		},
		{
			name: "bad signature",
			overrideAttestationData: func(data caws.IIDAttestationData) caws.IIDAttestationData {
				data.SignatureRSA2048 = "bad signature"
				return data
			},
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "nodeattestor(aws_iid): failed to parse the instance identity cryptographic signature",
		},
		{
			name:            "already attested",
			alreadyAttested: true,
			expectCode:      codes.PermissionDenied,
			expectMsgPrefix: "nodeattestor(aws_iid): attestation data has already been used to attest an agent",
		},
		{
			name:                   "DescribeInstances fails",
			describeInstancesError: errors.New("oh no"),
			expectCode:             codes.Internal,
			expectMsgPrefix:        "nodeattestor(aws_iid): failed to describe instance: oh no",
		},
		{
			name: "no reservations",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations = nil
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "nodeattestor(aws_iid): failed to query AWS via describe-instances: returned no reservations",
		},
		{
			name: "no instances in reservation",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances = nil
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "nodeattestor(aws_iid): failed to query AWS via describe-instances: returned no instances",
		},
		{
			name:            "signature verification fails using AWS CA cert from other region",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "nodeattestor(aws_iid): failed verification of instance identity cryptographic signature",
			overrideCACert:  otherAWSCACert,
		},
		{
			name:     "success with zero device index",
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
			},
		},
		{
			name: "success with RSA-1024 signature",
			overrideAttestationData: func(data caws.IIDAttestationData) caws.IIDAttestationData {
				data.SignatureRSA2048 = ""
				data.Signature = attentionDataWithRSA1024Signature.Signature
				return data
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
			},
		},
		{
			name:   "success with non-zero device index when check is disabled",
			config: "skip_block_device = true",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
			},
		},
		{
			name:   "success with non-zero device index when local account is allow-listed",
			config: `account_ids_for_local_validation = ["test-account"]`,
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
			},
		},
		{
			name: "block device anti-tampering check rejects non-zero network device index",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "nodeattestor(aws_iid): failed aws ec2 attestation: the EC2 instance network interface attachment device index must be zero (has 1)",
		},
		{
			name: "block device anti-tampering check fails to locate root device",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].RootDeviceName = aws.String("root")
				output.Reservations[0].Instances[0].RootDeviceType = ebsType
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: `nodeattestor(aws_iid): failed aws ec2 attestation: failed to locate the root device block mapping with name "root"`,
		},
		{
			name: "block device anti-tampering check fails when attach time too disparate",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				interfaceAttachTime := time.Now()
				blockDeviceAttachTime := interfaceAttachTime.Add(time.Second * time.Duration(maxSecondsBetweenDeviceAttachments+1))

				output.Reservations[0].Instances[0].RootDeviceName = aws.String("root")
				output.Reservations[0].Instances[0].RootDeviceType = ebsType
				output.Reservations[0].Instances[0].BlockDeviceMappings = []ec2types.InstanceBlockDeviceMapping{
					{
						DeviceName: aws.String("root"),
						Ebs: &ec2types.EbsInstanceBlockDevice{
							AttachTime: aws.Time(blockDeviceAttachTime),
						},
					},
				}
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.AttachTime = aws.Time(interfaceAttachTime)
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: `nodeattestor(aws_iid): failed aws ec2 attestation: failed checking the disparity device attach times, root BlockDeviceMapping and NetworkInterface[0] attach times differ by 61 seconds`,
		},
		{
			name: "block device anti-tampering check succeeds when attach time minimal",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				interfaceAttachTime := time.Now()
				blockDeviceAttachTime := interfaceAttachTime.Add(time.Second * time.Duration(maxSecondsBetweenDeviceAttachments))

				output.Reservations[0].Instances[0].RootDeviceName = aws.String("root")
				output.Reservations[0].Instances[0].RootDeviceType = ebsType
				output.Reservations[0].Instances[0].BlockDeviceMappings = []ec2types.InstanceBlockDeviceMapping{
					{
						DeviceName: aws.String("root"),
						Ebs: &ec2types.EbsInstanceBlockDevice{
							AttachTime: aws.Time(blockDeviceAttachTime),
						},
					},
				}
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.AttachTime = aws.Time(interfaceAttachTime)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
			},
		},
		{
			name:     "success with agent_path_template",
			config:   `agent_path_template = "/{{ .PluginName }}/custom/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}"`,
			expectID: "spiffe://example.org/spire/agent/aws_iid/custom/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
			},
		},
		{
			name: "success with tags in template",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].Tags = []ec2types.Tag{
					{
						Key:   aws.String("Hostname"),
						Value: aws.String("host1"),
					},
				}
			},
			config:   `agent_path_template = "/{{ .PluginName }}/zone1/{{ .Tags.Hostname }}"`,
			expectID: "spiffe://example.org/spire/agent/aws_iid/zone1/host1",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
				{Type: caws.PluginName, Value: "tag:Hostname:host1"},
			},
		},
		{
			name:            "fails with missing tags in template",
			config:          `agent_path_template = "/{{ .PluginName }}/zone1/{{ .Tags.Hostname }}"`,
			expectCode:      codes.Internal,
			expectMsgPrefix: `nodeattestor(aws_iid): failed to create spiffe ID: template: agent-path:1:33: executing "agent-path" at <.Tags.Hostname>: map has no entry for key "Hostname"`,
		},
		{
			name: "success with all the selectors",
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].Tags = []ec2types.Tag{
					{
						Key:   aws.String("Hostname"),
						Value: aws.String("host1"),
					},
				}
				output.Reservations[0].Instances[0].SecurityGroups = []ec2types.GroupIdentifier{
					{
						GroupId:   aws.String("TestGroup"),
						GroupName: aws.String("Test Group Name"),
					},
				}
				output.Reservations[0].Instances[0].IamInstanceProfile = &ec2types.IamInstanceProfile{
					Arn: aws.String("arn:aws::::instance-profile/" + testProfile),
				}
			},
			mutateGetInstanceProfileOutput: func(output *iam.GetInstanceProfileOutput) {
				output.InstanceProfile = &iamtypes.InstanceProfile{
					Roles: []iamtypes.Role{
						{Arn: aws.String("role1")},
						{Arn: aws.String("role2")},
					},
				}
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "iamrole:role1"},
				{Type: caws.PluginName, Value: "iamrole:role2"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
				{Type: caws.PluginName, Value: "sg:id:TestGroup"},
				{Type: caws.PluginName, Value: "sg:name:Test Group Name"},
				{Type: caws.PluginName, Value: "tag:Hostname:host1"},
			},
		},
		{
			name:   "success with instance profile selectors disabled",
			config: `disable_instance_profile_selectors = true`,
			mutateDescribeInstancesOutput: func(output *ec2.DescribeInstancesOutput) {
				output.Reservations[0].Instances[0].Tags = []ec2types.Tag{
					{
						Key:   aws.String("Hostname"),
						Value: aws.String("host1"),
					},
				}
				output.Reservations[0].Instances[0].SecurityGroups = []ec2types.GroupIdentifier{
					{
						GroupId:   aws.String("TestGroup"),
						GroupName: aws.String("Test Group Name"),
					},
				}
				output.Reservations[0].Instances[0].IamInstanceProfile = &ec2types.IamInstanceProfile{
					Arn: aws.String("arn:aws::::instance-profile/" + testProfile),
				}
			},
			mutateGetInstanceProfileOutput: func(output *iam.GetInstanceProfileOutput) {
				output.InstanceProfile = &iamtypes.InstanceProfile{
					Roles: []iamtypes.Role{
						{Arn: aws.String("role1")},
						{Arn: aws.String("role2")},
					},
				}
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "az:test-az"},
				{Type: caws.PluginName, Value: "image:id:test-image-id"},
				{Type: caws.PluginName, Value: "instance:id:test-instance"},
				{Type: caws.PluginName, Value: "region:test-region"},
				{Type: caws.PluginName, Value: "sg:id:TestGroup"},
				{Type: caws.PluginName, Value: "sg:name:Test Group Name"},
				{Type: caws.PluginName, Value: "tag:Hostname:host1"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := newFakeClient()
			client.DescribeInstancesError = tt.describeInstancesError
			if tt.mutateDescribeInstancesOutput != nil {
				tt.mutateDescribeInstancesOutput(client.DescribeInstancesOutput)
			}
			client.GetInstanceProfileError = tt.getInstanceProfileError
			if tt.mutateGetInstanceProfileOutput != nil {
				tt.mutateGetInstanceProfileOutput(client.GetInstanceProfileOutput)
			}

			agentStore := fakeagentstore.New()
			if tt.alreadyAttested {
				agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
					AgentId: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
				})
			}

			opts := []plugintest.Option{
				plugintest.HostServices(agentstorev1.AgentStoreServiceServer(agentStore)),
			}
			var configureErr error
			if !tt.skipConfigure {
				opts = append(opts,
					plugintest.Configure(tt.config),
					plugintest.CaptureConfigureError(&configureErr),
					plugintest.CoreConfig(catalog.CoreConfig{
						TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
					}),
				)
			}

			attestor := New()
			attestor.hooks.getenv = func(key string) string {
				return tt.env[key]
			}

			attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
				if tt.overrideCACert != nil {
					return otherAWSCACert, nil
				}
				return testAWSCACert, nil
			}

			attestor.clients = newClientsCache(func(ctx context.Context, config *SessionConfig, region string, assumeRoleARN string) (Client, error) {
				return client, nil
			})

			plugin := new(nodeattestor.V1)
			plugintest.Load(t, builtin(attestor), plugin, opts...)
			require.NoError(t, configureErr)

			attestationData := defaultAttestationData
			if tt.overrideAttestationData != nil {
				attestationData = tt.overrideAttestationData(attestationData)
			}
			payload := toJSON(t, attestationData)
			if tt.overridePayload != nil {
				payload = tt.overridePayload()
			}

			result, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				return
			}
			assert.Equal(t, tt.expectID, result.AgentID)
			spiretest.AssertProtoListEqual(t, tt.expectSelectors, result.Selectors)
		})
	}
}

func TestConfigure(t *testing.T) {
	env := map[string]string{}

	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string) error {
		var err error
		attestor := New()
		attestor.hooks.getenv = func(s string) string {
			return env[s]
		}
		plugintest.Load(t, builtin(attestor), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	t.Run("malformed", func(t *testing.T) {
		err := doConfig(t, coreConfig, "trust_domain")
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "expected start of object")
	})

	t.Run("missing trust domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, ``)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "core configuration has invalid trust domain: trust domain is missing")
	})

	t.Run("fails with access id but no secret", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		access_key_id = "ACCESSKEYID"
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration missing secret access key, but has access key id")
	})

	t.Run("fails with secret but no access id", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		secret_access_key = "SECRETACCESSKEY"
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration missing access key id, but has secret access key")
	})

	t.Run("bad agent template", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		agent_path_template = "/{{ .InstanceID "
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "failed to parse agent svid template")
	})

	t.Run("invalid partitions specified ", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		partition = "invalid-aws-partition"
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "invalid partition \"invalid-aws-partition\", must be one of: [aws aws-cn aws-us-gov]")
	})

	t.Run("success when valid partitions specified ", func(t *testing.T) {
		for _, partition := range partitions {
			err := doConfig(t, coreConfig, fmt.Sprintf("partition = %q", partition))
			require.NoError(t, err)
		}
	})

	t.Run("success with envvars", func(t *testing.T) {
		env[accessKeyIDVarName] = "ACCESSKEYID"
		env[secretAccessKeyVarName] = "SECRETACCESSKEY"
		defer func() {
			delete(env, accessKeyIDVarName)
			delete(env, secretAccessKeyVarName)
		}()
		err := doConfig(t, coreConfig, ``)
		require.NoError(t, err)
	})

	t.Run("success , no AWS keys", func(t *testing.T) {
		err := doConfig(t, coreConfig, ``)
		require.NoError(t, err)
	})
}

func TestInstanceProfileArnParsing(t *testing.T) {
	// not an ARN
	_, err := instanceProfileNameFromArn("not-an-arn")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "failed to parse arn: invalid prefix")

	// not an instance profile ARN
	_, err = instanceProfileNameFromArn("arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment")
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "arn is not for an instance profile")

	// success
	name, err := instanceProfileNameFromArn(testInstanceProfileArn)
	require.NoError(t, err)
	require.Equal(t, testInstanceProfileName, name)

	// check profiles with paths succeed (last part of arn is the profile name, path is ignored)
	name, err = instanceProfileNameFromArn(testInstanceProfileWithPathArn)
	require.NoError(t, err)
	require.Equal(t, testInstanceProfileName, name)
}

type fakeClient struct {
	DescribeInstancesOutput  *ec2.DescribeInstancesOutput
	DescribeInstancesError   error
	GetInstanceProfileOutput *iam.GetInstanceProfileOutput
	GetInstanceProfileError  error
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		DescribeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{
							RootDeviceType: instanceStoreType,
							NetworkInterfaces: []ec2types.InstanceNetworkInterface{
								{
									Attachment: &ec2types.InstanceNetworkInterfaceAttachment{
										DeviceIndex: &zeroDeviceIndex,
									},
								},
							},
						},
					},
				},
			},
		},
		GetInstanceProfileOutput: &iam.GetInstanceProfileOutput{},
	}
}

func (c *fakeClient) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	expectInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{testInstance},
		Filters:     instanceFilters,
	}
	if diff := cmp.Diff(input, expectInput, cmpopts.IgnoreUnexported(ec2.DescribeInstancesInput{}, ec2types.Filter{})); diff != "" {
		return nil, fmt.Errorf("unexpected request: %s", diff)
	}
	return c.DescribeInstancesOutput, c.DescribeInstancesError
}

func (c *fakeClient) GetInstanceProfile(_ context.Context, input *iam.GetInstanceProfileInput, _ ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error) {
	expectInput := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(testProfile),
	}
	if diff := cmp.Diff(input, expectInput, cmpopts.IgnoreUnexported(iam.GetInstanceProfileInput{})); diff != "" {
		return nil, fmt.Errorf("unexpected request: %s", diff)
	}
	return c.GetInstanceProfileOutput, c.GetInstanceProfileError
}

func buildAttestationDataRSA2048Signature(t *testing.T) caws.IIDAttestationData {
	// doc body
	doc := imds.InstanceIdentityDocument{
		AccountID:        testAccount,
		InstanceID:       testInstance,
		Region:           testRegion,
		AvailabilityZone: testAvailabilityZone,
		ImageID:          testImageID,
	}
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	signedData, err := pkcs7.NewSignedData(docBytes)
	require.NoError(t, err)

	privateKey := crypto.PrivateKey(testAWSCAKey)
	err = signedData.AddSigner(testAWSCACert, privateKey, pkcs7.SignerInfoConfig{})
	require.NoError(t, err)

	signature := generatePKCS7Signature(t, docBytes, testAWSCAKey)

	// base64 encode the signature
	signatureEncoded := base64.StdEncoding.EncodeToString(signature)

	return caws.IIDAttestationData{
		Document:         string(docBytes),
		SignatureRSA2048: signatureEncoded,
	}
}

func buildAttestationDataRSA1024Signature(t *testing.T) caws.IIDAttestationData {
	// doc body
	doc := imds.InstanceIdentityDocument{
		AccountID:        testAccount,
		InstanceID:       testInstance,
		Region:           testRegion,
		AvailabilityZone: testAvailabilityZone,
		ImageID:          testImageID,
	}
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	rng := rand.Reader
	docHash := sha256.Sum256(docBytes)
	sig, err := rsa.SignPKCS1v15(rng, testAWSCAKey, crypto.SHA256, docHash[:])
	require.NoError(t, err)

	signatureEncoded := base64.StdEncoding.EncodeToString(sig)

	return caws.IIDAttestationData{
		Document:  string(docBytes),
		Signature: signatureEncoded,
	}
}

func generatePKCS7Signature(t *testing.T, docBytes []byte, key *rsa.PrivateKey) []byte {
	signedData, err := pkcs7.NewSignedData(docBytes)
	require.NoError(t, err)

	cert := generateCertificate(t, key)
	privateKey := crypto.PrivateKey(key)
	err = signedData.AddSigner(cert, privateKey, pkcs7.SignerInfoConfig{})
	require.NoError(t, err)

	signature, err := signedData.Finish()
	require.NoError(t, err)

	return signature
}

func generateCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func toJSON(t *testing.T, obj any) []byte {
	jsonBytes, err := json.Marshal(obj)
	require.NoError(t, err)
	return jsonBytes
}

func expectNoChallenge(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}
