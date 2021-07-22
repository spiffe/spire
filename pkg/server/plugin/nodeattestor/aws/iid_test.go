package aws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/golang/mock/gomock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	mock_aws "github.com/spiffe/spire/test/mock/server/aws"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBzAIBAAJhAMnVzWSZn20CtcFaWh1Uuoh7NObRt9z84h8zzuIVSNkeJV6Dei0v
8FGp3ZilrU3MDM6WsuFTUVo21qBTOTnYKuEI0bk7pTgZk9CN6aF0iZbzyrvsU6hy
b09dN0PFBc5A2QIDAQABAmEAqSpioQvFPKfF0M46s1S9lwC1ATULRtRJbd+NaZ5v
VVLX/VRzRYZlhPy7d2J9U7ROFjSM+Fng8S1knrHAK0ka/ZfYOl1ZLoMexpBovebM
mGcsCHrHz4eBN8B1Y+8JRhkBAjEA7fTLjbz3M7za1nGODqWsoBv33yJHGh9GIaf9
umpx3qpFZCVsqHgCvmalAu+IXAz5AjEA2SPTRcddrGVsDnSOYot3eCArVOIxgI+r
H9A4cjS4cp4W4nBZhb+08/IYtDfYdirhAjAtl8LMtJE045GWlwld+xZ5UwKKSVoQ
Qj/AwRxXdH++5ycGijkoil4UNzyUtGqPIJkCMQC5g9ola8ekWqKPVxWvK+jOQO3E
f9w7MoPJkmQnbtOHWXnDzKkvlDJNmTFyB6RwkQECMQDp+GR2I305amG9isTzm7UU
8pJxbXLymDwR4A7x5vwH6x2gLBgpat21QAR14W4dYEg=
-----END RSA PRIVATE KEY-----`

	testInstanceProfileArn  = "arn:aws:iam::123412341234:instance-profile/nodes.test.k8s.local"
	testInstanceProfileName = "nodes.test.k8s.local"
)

var (
	testInstance       = "test-instance"
	testAccount        = "test-account"
	testRegion         = "test-region"
	testProfile        = "test-profile"
	zeroDeviceIndex    = int64(0)
	nonzeroDeviceIndex = int64(1)
	instanceStoreType  = ec2.DeviceTypeInstanceStore
)

func TestIIDAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(IIDAttestorSuite))
}

type IIDAttestorSuite struct {
	spiretest.Suite

	// original plugin, for modifications on mock
	plugin *IIDAttestorPlugin
	// built-in for full callstack
	attestor   nodeattestor.NodeAttestor
	rsaKey     *rsa.PrivateKey
	env        map[string]string
	agentStore *fakeagentstore.AgentStore
}

func (s *IIDAttestorSuite) SetupTest() {
	rsaKey, err := pemutil.ParseRSAPrivateKey([]byte(testRSAKey))
	s.Require().NoError(err)
	s.rsaKey = rsaKey

	s.env = make(map[string]string)
	s.agentStore = fakeagentstore.New()

	s.plugin, s.attestor = s.loadPlugin(nil, plugintest.Configure(`skip_block_device=true`),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
}

func (s *IIDAttestorSuite) TestErrorWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), BuiltIn(), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)

	s.attestor = attestor

	s.requireAttestError([]byte("{"), codes.FailedPrecondition, "nodeattestor(aws_iid): not configured")
}

func (s *IIDAttestorSuite) TestErrorOnMissingPayload() {
	s.requireAttestError(nil, codes.InvalidArgument, "payload cannot be empty")
}

func (s *IIDAttestorSuite) TestErrorOnMalformedPayload() {
	s.requireAttestError([]byte("malformed payload"), codes.InvalidArgument, "nodeattestor(aws_iid): failed to unmarshal the attestation data:")
}

func (s *IIDAttestorSuite) TestErrorOnAlreadyAttested() {
	mockCtrl := gomock.NewController(s.T())
	defer mockCtrl.Finish()

	client := mock_aws.NewMockClient(mockCtrl)

	mockGetEC2Client := func(config *SessionConfig, region string, asssumeRoleARN string) (Client, error) {
		return client, nil
	}
	clients := newClientsCache(mockGetEC2Client)

	plugin, attestor := s.loadPlugin(clients, plugintest.Configure(`skip_block_device=true`),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}))
	setAttestExpectations(client, getDefaultDescribeInstancesOutput(), nil)
	plugin.config.awsCaCertPublicKey = &s.rsaKey.PublicKey

	agentID := "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance"
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})

	payload := s.iidAttestationDataToBytes(*s.buildDefaultIIDAttestationData())

	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.RequireGRPCStatusContains(err, codes.PermissionDenied, "nodeattestor(aws_iid): IID has already been used to attest an agent")
	s.Require().Nil(result)
}

func (s *IIDAttestorSuite) TestErrorOnBadSignature() {
	iid := s.buildDefaultIIDAttestationData()
	iid.Signature = "bad sig"
	payload := s.iidAttestationDataToBytes(*iid)

	s.requireAttestError(payload, codes.InvalidArgument, "illegal base64 data at input byte")
}

func (s *IIDAttestorSuite) TestErrorOnNoSignature() {
	iid := s.buildDefaultIIDAttestationData()
	iid.Signature = ""
	payload := s.iidAttestationDataToBytes(*iid)

	s.requireAttestError(payload, codes.InvalidArgument, "failed to verify the cryptographic signature")
}

func (s *IIDAttestorSuite) TestClientAndIDReturns() {
	tests := []struct {
		desc                            string
		mockExpect                      func(mock *mock_aws.MockClient)
		expectID                        string
		expectSelectors                 []*common.Selector
		expectCode                      codes.Code
		expectMessage                   string
		replacementTemplate             string
		allowList                       []string
		skipBlockDev                    bool
		skipEC2Block                    bool
		disableInstanceProfileSelectors bool
	}{
		{
			desc: "error on call",
			mockExpect: func(mock *mock_aws.MockClient) {
				setAttestExpectations(mock, nil, errors.New("client error"))
			},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(aws_iid): failed to describe instance: client error",
		},
		{
			desc: "no reservation",
			mockExpect: func(mock *mock_aws.MockClient) {
				setAttestExpectations(mock, &ec2.DescribeInstancesOutput{
					Reservations: []*ec2.Reservation{},
				}, nil)
			},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(aws_iid): failed to query AWS via describe-instances: returned no reservations",
		},
		{
			desc: "no instance",
			mockExpect: func(mock *mock_aws.MockClient) {
				setAttestExpectations(mock, &ec2.DescribeInstancesOutput{
					Reservations: []*ec2.Reservation{
						{
							Instances: []*ec2.Instance{},
						},
					},
				}, nil)
			},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(aws_iid): failed to query AWS via describe-instances: returned no instances",
		},
		{
			desc: "non-zero device index",
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
				setAttestExpectations(mock, output, nil)
			},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(aws_iid): failed aws ec2 attestation: failed to verify the EC2 instance's NetworkInterface[0].DeviceIndex is 0, the DeviceIndex is 1",
		},
		{
			desc:         "success, client, no block device, default template",
			skipBlockDev: true,
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:         "success, client, no block device, other allowed acct, default template",
			skipBlockDev: true,
			allowList:    []string{"someOtherAccount"},
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:      "success, no client call, default template",
			allowList: []string{testAccount},
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:      "success, no client call, extra allowed acct, default template",
			allowList: []string{testAccount, "someOtherAccount"},
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:         "success, despite deprecated ec2 skip",
			allowList:    []string{testAccount},
			skipEC2Block: true,
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc: "success, client + block device, default template",
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc: "success, client + block device, different template",
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			replacementTemplate: "{{ .PluginName}}/{{ .Region }}/{{ .AccountID }}/{{ .InstanceID }}",
			expectID:            "spiffe://example.org/spire/agent/aws_iid/test-region/test-account/test-instance",
		},
		{
			desc: "success, tags in template",
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].Tags = []*ec2.Tag{
					{
						Key:   aws.String("Hostname"),
						Value: aws.String("host1"),
					},
				}
				output.Reservations[0].Instances[0].SecurityGroups = []*ec2.GroupIdentifier{
					{
						GroupId:   aws.String("TestGroup"),
						GroupName: aws.String("Test Group Name"),
					},
				}
				output.Reservations[0].Instances[0].IamInstanceProfile = &ec2.IamInstanceProfile{
					Arn: aws.String("arn:aws::::instance-profile/" + testProfile),
				}
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				gipo := &iam.GetInstanceProfileOutput{
					InstanceProfile: &iam.InstanceProfile{
						Roles: []*iam.Role{
							{Arn: aws.String("role1")},
							{Arn: aws.String("role2")},
						},
					},
				}
				setResolveSelectorsExpectations(mock, gipo)
			},
			replacementTemplate: "{{ .PluginName}}/zone1/{{ .Tags.Hostname }}",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "iamrole:role1"},
				{Type: caws.PluginName, Value: "iamrole:role2"},
				{Type: caws.PluginName, Value: "sg:id:TestGroup"},
				{Type: caws.PluginName, Value: "sg:name:Test Group Name"},
				{Type: caws.PluginName, Value: "tag:Hostname:host1"},
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/zone1/host1",
		},
		{
			desc: "missing tags do not panic",
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				setResolveSelectorsExpectations(mock, nil)
			},
			replacementTemplate: "{{ .PluginName}}/zone1/{{ .Tags.Hostname }}",
			expectID:            "spiffe://example.org/spire/agent/aws_iid/zone1/%3Cno%20value%3E",
		},
		{
			desc:                            "success, ignore instance profile selectors",
			disableInstanceProfileSelectors: true,
			mockExpect: func(mock *mock_aws.MockClient) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].Tags = []*ec2.Tag{
					{
						Key:   aws.String("Hostname"),
						Value: aws.String("host1"),
					},
				}
				output.Reservations[0].Instances[0].SecurityGroups = []*ec2.GroupIdentifier{
					{
						GroupId:   aws.String("TestGroup"),
						GroupName: aws.String("Test Group Name"),
					},
				}
				output.Reservations[0].Instances[0].IamInstanceProfile = &ec2.IamInstanceProfile{
					Arn: aws.String("arn:aws::::instance-profile/" + testProfile),
				}
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				setAttestExpectations(mock, output, nil)
				gipo := &iam.GetInstanceProfileOutput{
					InstanceProfile: &iam.InstanceProfile{
						Roles: []*iam.Role{
							{Arn: aws.String("role1")},
							{Arn: aws.String("role2")},
						},
					},
				}
				setResolveSelectorsExpectations(mock, gipo)
			},
			replacementTemplate: "{{ .PluginName}}/zone1/{{ .Tags.Hostname }}",
			expectSelectors: []*common.Selector{
				{Type: caws.PluginName, Value: "sg:id:TestGroup"},
				{Type: caws.PluginName, Value: "sg:name:Test Group Name"},
				{Type: caws.PluginName, Value: "tag:Hostname:host1"},
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/zone1/host1",
		},
	}

	for _, tt := range tests {
		tt := tt
		s.T().Run(tt.desc, func(t *testing.T) {
			mockCtl := gomock.NewController(s.T())
			defer mockCtl.Finish()

			client := mock_aws.NewMockClient(mockCtl)

			mockGetEC2Client := func(config *SessionConfig, region string, asssumeRoleARN string) (Client, error) {
				return client, nil
			}
			clients := newClientsCache(mockGetEC2Client)

			if tt.mockExpect != nil {
				tt.mockExpect(client)
			}

			var configStr string
			if tt.replacementTemplate != "" {
				configStr = fmt.Sprintf(`agent_path_template = "%s"`, tt.replacementTemplate)
			}
			if len(tt.allowList) > 0 {
				configStr += "\naccount_ids_for_local_validation = [\n"
				for _, id := range tt.allowList {
					configStr = `  ` + configStr + `"` + id + `",`
				}
				configStr += "\n]"
			}
			if tt.skipBlockDev {
				configStr += "\nskip_block_device = true"
			}
			if tt.skipEC2Block {
				configStr += "\nskip_ec2_attest_calling = true"
			}

			if tt.disableInstanceProfileSelectors {
				configStr += "\ndisable_instance_profile_selectors = true"
			}

			plugin, attestor := s.loadPlugin(clients, plugintest.Configure(configStr),
				plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}))

			payload := s.iidAttestationDataToBytes(*s.buildDefaultIIDAttestationData())

			// using our own keypair (since we don't have AWS private key)
			originalAWSPublicKey := plugin.config.awsCaCertPublicKey
			defer func() {
				plugin.config.awsCaCertPublicKey = originalAWSPublicKey
			}()
			plugin.config.awsCaCertPublicKey = &s.rsaKey.PublicKey

			resp, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
			s.AssertGRPCStatusContains(err, tt.expectCode, tt.expectMessage)
			if tt.expectMessage != "" {
				s.Nil(resp)
				return
			}

			s.Equal(tt.expectID, resp.AgentID)
			if tt.expectSelectors != nil {
				s.Len(resp.Selectors, len(tt.expectSelectors))
				for i, sel := range resp.Selectors {
					s.Equal(tt.expectSelectors[i], sel)
				}
			}
		})
	}
}

func (s *IIDAttestorSuite) TestErrorOnBadSVIDTemplate() {
	var err error
	plugintest.Load(s.T(), BuiltIn(), nil,
		plugintest.CaptureConfigureError(&err),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`
agent_path_template = "{{ .InstanceID "
`),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "failed to parse agent svid template")
}

func (s *IIDAttestorSuite) TestConfigure() {
	env := map[string]string{}

	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string) error {
		var err error
		attestor := New()
		attestor.hooks.getenv = func(s string) string {
			return env[s]
		}

		plugintest.Load(t, builtin(attestor), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed", func(t *testing.T) {
		err := doConfig(t, coreConfig, "trust_domain")
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "expected start of object")
	})

	s.T().Run("missing trust domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, ``)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "core configuration missing trust domain")
	})

	s.T().Run("fails with access id but no secret", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		access_key_id = "ACCESSKEYID"
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration missing secret access key, but has access key id")
	})

	s.T().Run("fails with secret but no access id", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		secret_access_key = "SECRETACCESSKEY"
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "configuration missing access key id, but has secret access key")
	})

	s.T().Run("success with envvars", func(t *testing.T) {
		env[accessKeyIDVarName] = "ACCESSKEYID"
		env[secretAccessKeyVarName] = "SECRETACCESSKEY"
		defer func() {
			delete(env, accessKeyIDVarName)
			delete(env, secretAccessKeyVarName)
		}()
		err := doConfig(t, coreConfig, ``)
		require.NoError(t, err)
	})

	s.T().Run("success , no AWS keys", func(t *testing.T) {
		err := doConfig(t, coreConfig, ``)
		require.NoError(t, err)
	})
}

func (s *IIDAttestorSuite) TestInstanceProfileArnParsing() {
	// not an ARN
	_, err := instanceProfileNameFromArn("not-an-arn")

	s.RequireGRPCStatus(err, codes.Internal, "failed to parse arn: invalid prefix")

	// not an instance profile ARN
	_, err = instanceProfileNameFromArn("arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment")
	s.RequireGRPCStatus(err, codes.Internal, "arn is not for an instance profile")

	name, err := instanceProfileNameFromArn(testInstanceProfileArn)
	s.Require().NoError(err)
	s.Require().Equal(testInstanceProfileName, name)
}

// get a DescribeInstancesOutput with essential structs created, but no values
// (device index and root device type) filled out
func getDefaultDescribeInstancesOutput() *ec2.DescribeInstancesOutput {
	return &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					{
						NetworkInterfaces: []*ec2.InstanceNetworkInterface{
							{
								Attachment: &ec2.InstanceNetworkInterfaceAttachment{},
							},
						},
					},
				},
			},
		},
	}
}

func (s *IIDAttestorSuite) buildIIDAttestationData(instanceID, accountID, region string) *caws.IIDAttestationData {
	// doc body
	doc := ec2metadata.EC2InstanceIdentityDocument{
		AccountID:  accountID,
		InstanceID: instanceID,
		Region:     region,
	}
	docBytes, err := json.Marshal(doc)
	s.Require().NoError(err)

	// doc signature
	rng := rand.Reader
	docHash := sha256.Sum256(docBytes)
	sig, err := rsa.SignPKCS1v15(rng, s.rsaKey, crypto.SHA256, docHash[:])
	s.Require().NoError(err)

	return &caws.IIDAttestationData{
		Document:  string(docBytes),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

func (s *IIDAttestorSuite) buildDefaultIIDAttestationData() *caws.IIDAttestationData {
	return s.buildIIDAttestationData(testInstance, testAccount, testRegion)
}

func (s *IIDAttestorSuite) iidAttestationDataToBytes(data caws.IIDAttestationData) []byte {
	dataBytes, err := json.Marshal(data)
	s.Require().NoError(err)
	return dataBytes
}

func (s *IIDAttestorSuite) loadPlugin(clients *clientsCache, opts ...plugintest.Option) (*IIDAttestorPlugin, nodeattestor.NodeAttestor) {
	attestor := New()

	// Set env vars
	attestor.hooks.getenv = func(key string) string {
		return s.env[key]
	}
	if clients != nil {
		attestor.clients = clients
	}

	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(attestor), v1, opts...)

	return attestor, v1
}

func (s *IIDAttestorSuite) requireAttestError(payload []byte, expectCode codes.Code, expectMsg string) {
	result, err := s.attestor.Attest(context.Background(), payload, expectNoChallenge)
	s.RequireGRPCStatusContains(err, expectCode, expectMsg)
	s.Require().Nil(result)
}

func setAttestExpectations(mock *mock_aws.MockClient, dio *ec2.DescribeInstancesOutput, err error) {
	mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
		InstanceIds: []*string{&testInstance},
		Filters:     instanceFilters,
	}).Return(dio, err)
}

func setResolveSelectorsExpectations(mock *mock_aws.MockClient, gipo *iam.GetInstanceProfileOutput) {
	mock.EXPECT().GetInstanceProfileWithContext(gomock.Any(), &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(testProfile),
	}).AnyTimes().Return(gipo, nil)
}

func expectNoChallenge(ctx context.Context, challenge []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}
