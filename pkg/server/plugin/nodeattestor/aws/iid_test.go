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
	"io"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc/codes"

	"github.com/spiffe/spire/pkg/common/plugin/aws"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	mock_aws "github.com/spiffe/spire/test/mock/server/aws"
	"github.com/spiffe/spire/test/spiretest"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
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
)

var (
	testInstance = "test-instance"
	testAccount  = "test-account"
	testRegion   = "test-region"
)

func TestIIDAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(IIDAttestorSuite))
}

type IIDAttestorSuite struct {
	spiretest.Suite

	// original plugin, for modifications on mock
	plugin *IIDAttestorPlugin
	// built-in for full callstack
	p          nodeattestor.Plugin
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

	p := New()
	p.hooks.getEnv = func(key string) string {
		return s.env[key]
	}
	s.plugin = p
	s.LoadPlugin(builtin(s.plugin), &s.p,
		spiretest.HostService(hostservices.AgentStoreHostServiceServer(s.agentStore)),
	)
}

func (s *IIDAttestorSuite) TestErrorWhenNotConfigured() {
	// the stream should open but the plugin should immediately return an error
	stream, err := s.p.Attest(context.Background())
	s.Require().NoError(err)
	defer stream.CloseSend()

	// Send() will either succeed or return EOF if the gRPC stream has already
	// been torn down due to the plugin-side failure.
	err = stream.Send(&nodeattestor.AttestRequest{})
	if err != nil && err != io.EOF {
		s.Require().NoError(err)
	}

	// Recv() should fail.
	_, err = stream.Recv()
	s.RequireGRPCStatus(err, codes.Unknown, "not configured")
}

func (s *IIDAttestorSuite) TestErrorOnEmptyRequest() {
	s.configure()

	_, err := s.attest(&nodeattestor.AttestRequest{})
	s.RequireErrorContains(err, "request missing attestation data")
}

func (s *IIDAttestorSuite) TestErrorOnInvalidType() {
	s.configure()

	_, err := s.attest(&nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: "foo",
		},
	})
	s.RequireErrorContains(err, `unexpected attestation data type "foo"`)
}

func (s *IIDAttestorSuite) TestErrorOnMissingData() {
	s.configure()

	data := &common.AttestationData{
		Type: aws.PluginName,
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.RequireErrorContains(err, "unexpected end of JSON input")
}

func (s *IIDAttestorSuite) TestErrorOnBadData() {
	s.configure()

	data := &common.AttestationData{
		Type: aws.PluginName,
		Data: make([]byte, 0),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{AttestationData: data})
	s.RequireErrorContains(err, "unexpected end of JSON input")
}

func (s *IIDAttestorSuite) TestErrorOnAlreadyAttested() {
	s.configure()

	// using our own keypair (since we don't have AWS private key)
	originalAWSPublicKey := s.plugin.config.awsCaCertPublicKey
	defer func() {
		s.plugin.config.awsCaCertPublicKey = originalAWSPublicKey
	}()
	s.plugin.config.awsCaCertPublicKey = &s.rsaKey.PublicKey

	data := &common.AttestationData{
		Type: aws.PluginName,
		Data: s.iidAttestationDataToBytes(*s.buildDefaultIIDAttestationData()),
	}

	agentID := "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance"
	s.agentStore.SetAgentInfo(&hostservices.AgentInfo{
		AgentId: agentID,
	})

	_, err := s.attest(&nodeattestor.AttestRequest{
		AttestationData: data,
	})
	s.RequireErrorContains(err, "IID has already been used to attest an agent")
}

func (s *IIDAttestorSuite) TestErrorOnBadSignature() {
	s.configure()

	iid := s.buildDefaultIIDAttestationData()
	iid.Signature = "bad sig"
	data := &common.AttestationData{
		Type: aws.PluginName,
		Data: s.iidAttestationDataToBytes(*iid),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{
		AttestationData: data,
	})
	s.RequireErrorContains(err, "illegal base64 data at input byte")
}

func (s *IIDAttestorSuite) TestErrorOnNoSignature() {
	s.configure()

	iid := s.buildDefaultIIDAttestationData()
	iid.Signature = ""
	data := &common.AttestationData{
		Type: aws.PluginName,
		Data: s.iidAttestationDataToBytes(*iid),
	}

	_, err := s.attest(&nodeattestor.AttestRequest{
		AttestationData: data,
	})
	s.RequireErrorContains(err, "verifying the cryptographic signature")
}

func (s *IIDAttestorSuite) TestClientAndIDReturns() {
	zeroDeviceIndex := int64(0)
	nonzeroDeviceIndex := int64(1)
	instanceStoreType := ec2.DeviceTypeInstanceStore

	tests := []struct {
		desc                string
		mockExpect          func(mock *mock_aws.MockEC2Client)
		expectID            string
		expectErr           string
		replacementTemplate string
		allowList           []string
		skipBlockDev        bool
		skipEC2Block        bool
	}{
		{
			desc: "error on call",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(nil, errors.New("client error"))
			},
			expectErr: "client error",
		},
		{
			desc: "no reservation",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&ec2.DescribeInstancesOutput{
					Reservations: []*ec2.Reservation{},
				}, nil)
			},
			expectErr: "querying AWS via describe-instances: returned no reservations",
		},
		{
			desc: "no instance",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&ec2.DescribeInstancesOutput{
					Reservations: []*ec2.Reservation{
						{
							Instances: []*ec2.Instance{},
						},
					},
				}, nil)
			},
			expectErr: "querying AWS via describe-instances: returned no instances",
		},
		{
			desc: "non-zero device index",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &nonzeroDeviceIndex
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&output, nil)
			},
			expectErr: "verifying the EC2 instance's NetworkInterface[0].DeviceIndex is 0",
		},
		{
			desc:         "success, client, no block device, default template",
			skipBlockDev: true,
			expectID:     "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:         "success, client, no block device, other allowed acct, default template",
			skipBlockDev: true,
			allowList:    []string{"someOtherAccount"},
			expectID:     "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:      "success, no client call, default template",
			allowList: []string{testAccount},
			expectID:  "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:      "success, no client call, extra allowed acct, default template",
			allowList: []string{testAccount, "someOtherAccount"},
			expectID:  "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc:         "success, despite deprecated ec2 skip",
			allowList:    []string{testAccount},
			skipEC2Block: true,
			expectID:     "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc: "success, client + block device, default template",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&output, nil)
			},
			expectID: "spiffe://example.org/spire/agent/aws_iid/test-account/test-region/test-instance",
		},
		{
			desc: "success, client + block device, different template",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&output, nil)
			},
			replacementTemplate: "{{ .PluginName}}/{{ .Region }}/{{ .AccountID }}/{{ .InstanceID }}",
			expectID:            "spiffe://example.org/spire/agent/aws_iid/test-region/test-account/test-instance",
		},
		{
			desc: "success, tags in template",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].Tags = []*ec2.Tag{
					{
						Key:   func() *string { a := "Hostname"; return &a }(),
						Value: func() *string { a := "host1"; return &a }(),
					},
				}
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&output, nil)
			},
			replacementTemplate: "{{ .PluginName}}/zone1/{{ .Tags.Hostname }}",
			expectID:            "spiffe://example.org/spire/agent/aws_iid/zone1/host1",
		},
		{
			desc: "missing tags do not panic",
			mockExpect: func(mock *mock_aws.MockEC2Client) {
				output := getDefaultDescribeInstancesOutput()
				output.Reservations[0].Instances[0].RootDeviceType = &instanceStoreType
				output.Reservations[0].Instances[0].NetworkInterfaces[0].Attachment.DeviceIndex = &zeroDeviceIndex
				mock.EXPECT().DescribeInstancesWithContext(gomock.Any(), &ec2.DescribeInstancesInput{
					InstanceIds: []*string{&testInstance},
				}).Return(&output, nil)
			},
			replacementTemplate: "{{ .PluginName}}/zone1/{{ .Tags.Hostname }}",
			expectID:            "spiffe://example.org/spire/agent/aws_iid/zone1/%3Cno%20value%3E",
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.desc, func(t *testing.T) {
			mockCtl := gomock.NewController(s.T())
			defer mockCtl.Finish()

			ec2Client := mock_aws.NewMockEC2Client(mockCtl)

			originalGetEC2Client := s.plugin.hooks.getClient
			defer func() {
				s.plugin.hooks.getClient = originalGetEC2Client
			}()
			mockGetEC2Client := func(p client.ConfigProvider, cfgs ...*awssdk.Config) EC2Client {
				return ec2Client
			}
			s.plugin.hooks.getClient = mockGetEC2Client
			if tt.mockExpect != nil {
				tt.mockExpect(ec2Client)
			}

			var configStr string
			if tt.replacementTemplate != "" {
				configStr = fmt.Sprintf(`agent_path_template = "%s"`, tt.replacementTemplate)
			}
			if len(tt.allowList) > 0 {
				configStr = configStr + "\naccount_ids_for_local_validation = [\n"
				for _, id := range tt.allowList {
					configStr = `  ` + configStr + `"` + id + `",`
				}
				configStr = configStr + "\n]"
			}
			if tt.skipBlockDev {
				configStr = configStr + "\nskip_block_device = true"
			}
			if tt.skipEC2Block {
				configStr = configStr + "\nskip_ec2_attest_calling = true"
			}

			_, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
				Configuration: configStr,
				GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
			})
			s.Require().NoError(err)

			data := &common.AttestationData{
				Type: aws.PluginName,
				Data: s.iidAttestationDataToBytes(*s.buildDefaultIIDAttestationData()),
			}

			// using our own keypair (since we don't have AWS private key)
			originalAWSPublicKey := s.plugin.config.awsCaCertPublicKey
			defer func() {
				s.plugin.config.awsCaCertPublicKey = originalAWSPublicKey
			}()
			s.plugin.config.awsCaCertPublicKey = &s.rsaKey.PublicKey

			resp, err := s.attest(&nodeattestor.AttestRequest{
				AttestationData: data,
			})

			if tt.expectErr != "" {
				s.Nil(resp)
				s.RequireErrorContains(err, tt.expectErr)
				return
			}

			s.Equal(tt.expectID, resp.AgentId)
		})
	}
}

func (s *IIDAttestorSuite) TestErrorOnBadSVIDTemplate() {
	_, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
agent_path_template = "{{ .InstanceID "
`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.RequireErrorContains(err, "failed to parse agent svid template")
}

func (s *IIDAttestorSuite) TestConfigure() {
	require := s.Require()

	// malformed
	resp, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `trust_domain`,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.RequireErrorContains(err, "expected start of object")
	require.Nil(resp)

	// missing global configuration
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: ``})
	s.RequireErrorContains(err, "global configuration is required")
	require.Nil(resp)

	// missing trust domain
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: ``,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{}})
	s.RequireErrorContains(err, "trust_domain is required")
	require.Nil(resp)

	// fails with access id but no secret
	resp, err = s.plugin.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		access_key_id = "ACCESSKEYID"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"}})
	s.Require().EqualError(err, "configuration missing secret access key, but has access key id")
	s.Require().Nil(resp)

	// fails with secret but no access id
	resp, err = s.plugin.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `
		secret_access_key = "SECRETACCESSKEY"
		`,
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"}})
	s.Require().EqualError(err, "configuration missing access key id, but has secret access key")
	s.Require().Nil(resp)

	// success with envvars
	s.env[caws.AccessKeyIDVarName] = "ACCESSKEYID"
	s.env[caws.SecretAccessKeyVarName] = "SECRETACCESSKEY"
	resp, err = s.plugin.Configure(context.Background(), &plugin.ConfigureRequest{
		GlobalConfig: &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
	s.Require().Equal(resp, &plugin.ConfigureResponse{})
	delete(s.env, caws.AccessKeyIDVarName)
	delete(s.env, caws.SecretAccessKeyVarName)

	// success, no AWS keys
	resp, err = s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: ``,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"}})
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(resp, &plugin.ConfigureResponse{})
}

func (s *IIDAttestorSuite) TestGetPluginInfo() {
	require := s.Require()
	resp, err := s.p.GetPluginInfo(context.Background(), &plugin.GetPluginInfoRequest{})
	require.NoError(err)
	require.NotNil(resp)
	require.Equal(resp, &plugin.GetPluginInfoResponse{})
}

func (s *IIDAttestorSuite) configure() {
	_, err := s.p.Configure(context.Background(), &plugin.ConfigureRequest{
		Configuration: `skip_block_device=true`,
		GlobalConfig:  &plugin.ConfigureRequest_GlobalConfig{TrustDomain: "example.org"},
	})
	s.Require().NoError(err)
}

// get a DescribeInstancesOutput with essential structs created, but no values
// (device index and root device type) filled out
func getDefaultDescribeInstancesOutput() ec2.DescribeInstancesOutput {
	return ec2.DescribeInstancesOutput{
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

func (s *IIDAttestorSuite) attest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	stream, err := s.p.Attest(context.Background())
	s.Require().NoError(err)
	defer stream.CloseSend()
	err = stream.Send(req)
	s.Require().NoError(err)
	return stream.Recv()
}

func (s *IIDAttestorSuite) buildIIDAttestationData(instanceID, accountID, region string) *aws.IIDAttestationData {
	// doc body
	doc := aws.InstanceIdentityDocument{
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

	return &aws.IIDAttestationData{
		Document:  string(docBytes),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

func (s *IIDAttestorSuite) buildDefaultIIDAttestationData() *aws.IIDAttestationData {
	return s.buildIIDAttestationData(testInstance, testAccount, testRegion)
}

func (s *IIDAttestorSuite) iidAttestationDataToBytes(data aws.IIDAttestationData) []byte {
	dataBytes, err := json.Marshal(data)
	s.Require().NoError(err)
	return dataBytes
}
