package awsiid

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

func TestPartitionCredentialsRouteAWSClients(t *testing.T) {
	var calls []struct {
		partition string
		key       string
		role      string
		region    string
	}
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, region, role, _ string) (Client, error) {
		calls = append(calls, struct {
			partition string
			key       string
			role      string
			region    string
		}{config.Partition, config.AccessKeyID, role, region})
		return &fakeClient{}, nil
	})
	var configureErr error
	plugintest.Load(t, builtin(attestor), nil,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(`partition_credentials {
    aws {
        access_key_id = "COMMERCIAL"
        secret_access_key = "commercial-secret"
        assume_role = "attestor"
    }
    aws-us-gov {
        access_key_id = "GOVERNMENT"
        secret_access_key = "government-secret"
        assume_role = "attestor"
    }
}`),
	)
	require.NoError(t, configureErr)
	for _, region := range []string{"us-east-1", "us-gov-west-1", "us-east-1", "us-gov-west-1"} {
		_, err := attestor.clients.getClient(context.Background(), region, "123456789012")
		require.NoError(t, err)
	}
	require.Len(t, calls, 2, "a cached client must be specific to the region and partition")
	require.Equal(t, "aws", calls[0].partition)
	require.Equal(t, "COMMERCIAL", calls[0].key)
	require.Equal(t, "arn:aws:iam::123456789012:role/attestor", calls[0].role)
	require.Equal(t, "aws-us-gov", calls[1].partition)
	require.Equal(t, "GOVERNMENT", calls[1].key)
	require.Equal(t, "arn:aws-us-gov:iam::123456789012:role/attestor", calls[1].role)

	_, err := attestor.clients.getClient(context.Background(), "cn-north-1", "123456789012")
	require.Error(t, err, "missing partition must fail without trying another partition")
	require.Len(t, calls, 2)
	_, err = attestor.clients.getClient(context.Background(), "us-gov-west-1", "987654321098")
	require.NoError(t, err)
	require.Len(t, calls, 3)
	require.Equal(t, "arn:aws-us-gov:iam::987654321098:role/attestor", calls[2].role)

	_, err = attestor.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  `partition_credentials { aws { access_key_id = "REPLACED" secret_access_key = "new-secret" } }`,
	})
	require.NoError(t, err)
	_, err = attestor.clients.getClient(context.Background(), "us-gov-west-1", "123456789012")
	require.Error(t, err, "a removed partition must not reuse its cached client")
	require.Len(t, calls, 3)
	_, err = attestor.clients.getClient(context.Background(), "us-east-1", "123456789012")
	require.NoError(t, err)
	require.Len(t, calls, 4, "reconfiguration must invalidate the old cached client")
	require.Equal(t, "REPLACED", calls[3].key)
}

func TestPartitionCredentialsDocumentation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(util.ProjectRoot(), "doc/plugin_server_nodeattestor_aws_iid.md"))
	require.NoError(t, err)
	for _, term := range []string{
		"partition_credentials", "aws-cn", "aws-us-gov", "access_key_id", "secret_access_key",
		"web_identity_role_arn", "web_identity_token_file", "assume_role",
		"ec2:DescribeInstances", "iam:GetInstanceProfile", "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity",
		"organizations:ListAccounts", "eks:ListNodegroups", "eks:DescribeNodegroup",
		"autoscaling:DescribeAutoScalingGroups",
	} {
		require.Contains(t, string(data), term)
	}
}

func TestUnconfiguredPartitionFailsBeforeAWSCalls(t *testing.T) {
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return generateCertificate(t, testAWSCAKey), nil
	}
	calls := 0
	attestor.clients = newClientsCache(func(context.Context, *SessionConfig, string, string, string) (Client, error) {
		calls++
		return newFakeClient(), nil
	})
	var configureErr error
	plugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(attestor), plugin,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(`verify_organization = { management_account_id = "12345" assume_org_role = "org-reader" management_account_region = "us-east-1" }
partition_credentials { aws { access_key_id = "COMMERCIAL" secret_access_key = "secret" } }`),
	)
	require.NoError(t, configureErr)
	for _, region := range []string{"cn-north-1", "us-gov-west-1", "eusc-de-east-1"} {
		t.Run(region, func(t *testing.T) {
			payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
				AccountID: "123456789012", InstanceID: "i-123", Region: region, AvailabilityZone: region + "a", ImageID: "ami-123",
			}))
			_, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
			require.Error(t, err)
			require.Equal(t, 0, calls)
		})
	}
}

func TestPartitionLookupFailureDoesNotFallBack(t *testing.T) {
	for _, stage := range []string{"instance", "EKS"} {
		t.Run(stage, func(t *testing.T) {
			attestor := New()
			attestor.hooks.getenv = func(string) string { return "" }
			attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
				return generateCertificate(t, testAWSCAKey), nil
			}
			var selected []string
			attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, _, _, _ string) (Client, error) {
				selected = append(selected, config.Partition)
				client := newFakeClient()
				if config.Partition == "aws-us-gov" {
					if stage == "instance" {
						client.DescribeInstancesError = fmt.Errorf("selected partition instance lookup failed")
					} else {
						client.ListNodegroupsError = fmt.Errorf("selected partition EKS lookup failed")
					}
				}
				return client, nil
			})
			configuration := `skip_block_device = true
partition_credentials {
    aws { access_key_id = "COMMERCIAL" secret_access_key = "secret" }
    aws-us-gov { access_key_id = "GOVERNMENT" secret_access_key = "secret" }
}`
			if stage == "EKS" {
				configuration += `
validate_eks_cluster_membership = { eks_cluster_names = ["test-cluster"] }`
			}
			var configureErr error
			plugin := new(nodeattestor.V1)
			plugintest.Load(t, builtin(attestor), plugin,
				plugintest.CaptureConfigureError(&configureErr),
				plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
				plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
				plugintest.Configure(configuration),
			)
			require.NoError(t, configureErr)
			payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
				AccountID: "123456789012", InstanceID: testInstance, Region: "us-gov-west-1", AvailabilityZone: "us-gov-west-1a", ImageID: "ami-123",
			}))
			_, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
			require.Error(t, err, "a failed lookup must fail attestation")
			require.Equal(t, []string{"aws-us-gov"}, selected, "a failed lookup must not try another partition")
		})
	}
}

func TestPartitionProfileAndOrganizationFailuresDoNotFallBack(t *testing.T) {
	for _, stage := range []string{"profile", "organization"} {
		t.Run(stage, func(t *testing.T) {
			attestor := New()
			attestor.hooks.getenv = func(string) string { return "" }
			attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
				return generateCertificate(t, testAWSCAKey), nil
			}
			var selected []string
			attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, _, _, _ string) (Client, error) {
				selected = append(selected, config.Partition)
				client := newFakeClient()
				if stage == "profile" && config.Partition == "aws-us-gov" {
					profileARN := "arn:aws-us-gov:iam::123456789012:instance-profile/test-profile"
					client.DescribeInstancesOutput.Reservations[0].Instances[0].IamInstanceProfile = &ec2types.IamInstanceProfile{Arn: &profileARN}
					client.GetInstanceProfileError = fmt.Errorf("selected partition profile lookup failed")
				}
				if stage == "organization" && config.Partition == "aws-us-gov" {
					client.ListAccountError = fmt.Errorf("selected partition organization lookup failed")
				}
				return client, nil
			})
			configuration := `skip_block_device = true
partition_credentials {
    aws { access_key_id = "COMMERCIAL" secret_access_key = "secret" }
    aws-us-gov { access_key_id = "GOVERNMENT" secret_access_key = "secret" }
}`
			if stage == "organization" {
				configuration += `
verify_organization = { management_account_id = "12345" assume_org_role = "org-reader" management_account_region = "us-gov-west-1" }`
			}
			var configureErr error
			plugin := new(nodeattestor.V1)
			plugintest.Load(t, builtin(attestor), plugin,
				plugintest.CaptureConfigureError(&configureErr),
				plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
				plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
				plugintest.Configure(configuration),
			)
			require.NoError(t, configureErr)
			region := "us-east-1"
			if stage == "profile" {
				region = "us-gov-west-1"
			}
			payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
				AccountID: "123456789012", InstanceID: testInstance, Region: region, AvailabilityZone: region + "a", ImageID: "ami-123",
			}))
			_, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
			require.Error(t, err)
			require.Equal(t, []string{"aws-us-gov"}, selected)
		})
	}
}

func TestInvalidSignedDocumentNeverSelectsCredentials(t *testing.T) {
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return generateCertificate(t, testAWSCAKey), nil
	}
	var selected []string
	attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, _, _, _ string) (Client, error) {
		selected = append(selected, config.Partition)
		return newFakeClient(), nil
	})
	var configureErr error
	plugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(attestor), plugin,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(`skip_block_device = true
partition_credentials { aws-cn { access_key_id = "CHINA" secret_access_key = "secret" } }`),
	)
	require.NoError(t, configureErr)
	data := buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
		AccountID: "123456789012", InstanceID: testInstance, Region: "cn-north-1", AvailabilityZone: "cn-north-1a", ImageID: "ami-123",
	})
	data.SignatureRSA2048 = "bad signature"
	_, err := plugin.Attest(context.Background(), toJSON(t, data), expectNoChallenge)
	require.Error(t, err)
	require.Empty(t, selected, "invalid signatures must be rejected before selecting AWS credentials")
	validPayload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
		AccountID: "123456789012", InstanceID: testInstance, Region: "cn-north-1", AvailabilityZone: "cn-north-1a", ImageID: "ami-123",
	}))
	_, err = plugin.Attest(context.Background(), validPayload, expectNoChallenge)
	require.NoError(t, err)
	require.Equal(t, []string{"aws-cn"}, selected, "a verified China IID must select its own credentials")
}

type partitionEKSClient struct {
	*fakeClient
	partition  string
	instanceID string
	events     *[]string
}

func (c *partitionEKSClient) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if len(input.InstanceIds) != 1 || input.InstanceIds[0] != c.instanceID {
		return nil, fmt.Errorf("unexpected instance request for %v", input.InstanceIds)
	}
	return c.fakeClient.DescribeInstancesOutput, c.fakeClient.DescribeInstancesError
}

func (c *partitionEKSClient) ListNodegroups(ctx context.Context, input *eks.ListNodegroupsInput, opts ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error) {
	*c.events = append(*c.events, c.partition+":ListNodegroups")
	return c.fakeClient.ListNodegroups(ctx, input, opts...)
}

func (c *partitionEKSClient) DescribeNodegroup(ctx context.Context, input *eks.DescribeNodegroupInput, opts ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error) {
	*c.events = append(*c.events, c.partition+":DescribeNodegroup")
	return c.fakeClient.DescribeNodegroup(ctx, input, opts...)
}

func (c *partitionEKSClient) DescribeAutoScalingGroups(ctx context.Context, input *autoscaling.DescribeAutoScalingGroupsInput, opts ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	*c.events = append(*c.events, c.partition+":DescribeAutoScalingGroups")
	return c.fakeClient.DescribeAutoScalingGroups(ctx, input, opts...)
}

func TestMultiPartitionSignedAttestation(t *testing.T) {
	certificate := generateCertificate(t, testAWSCAKey)
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return certificate, nil
	}
	var selected, eksEvents []string
	attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, region, _, _ string) (Client, error) {
		selected = append(selected, config.Partition+":"+config.AccessKeyID)
		client := newFakeClient()
		instanceID := testInstance
		switch region {
		case "us-gov-west-1":
			instanceID = "i-gov-node"
			profileARN := "arn:aws-us-gov:iam::123456789012:instance-profile/test-profile"
			roleARN := "arn:aws-us-gov:iam::123456789012:role/profile-reader"
			client.DescribeInstancesOutput.Reservations[0].Instances[0].IamInstanceProfile = &ec2types.IamInstanceProfile{Arn: &profileARN}
			client.GetInstanceProfileOutput.InstanceProfile = &iamtypes.InstanceProfile{Roles: []iamtypes.Role{{Arn: &roleARN}}}
		case "cn-north-1":
			instanceID = "i-china-node"
			profileARN := "arn:aws-cn:iam::123456789012:instance-profile/test-profile"
			roleARN := "arn:aws-cn:iam::123456789012:role/profile-reader"
			client.DescribeInstancesOutput.Reservations[0].Instances[0].IamInstanceProfile = &ec2types.IamInstanceProfile{Arn: &profileARN}
			client.GetInstanceProfileOutput.InstanceProfile = &iamtypes.InstanceProfile{Roles: []iamtypes.Role{{Arn: &roleARN}}}
		}
		client.DescribeAutoScalingGroupsOutput.AutoScalingGroups[0].Instances[0].InstanceId = &instanceID
		return &partitionEKSClient{fakeClient: client, partition: config.Partition, instanceID: instanceID, events: &eksEvents}, nil
	})
	var configureErr error
	plugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(attestor), plugin,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(`skip_block_device = true
validate_eks_cluster_membership = { eks_cluster_names = ["test-cluster"] }
partition_credentials {
    aws { access_key_id = "COMMERCIAL" secret_access_key = "secret" }
    aws-us-gov { access_key_id = "GOVERNMENT" secret_access_key = "secret" }
    aws-cn { access_key_id = "CHINA" secret_access_key = "secret" }
}`),
	)
	require.NoError(t, configureErr)
	for _, region := range []string{"us-east-1", "us-gov-west-1", "cn-north-1"} {
		start := len(eksEvents)
		instanceID := testInstance
		switch region {
		case "us-gov-west-1":
			instanceID = "i-gov-node"
		case "cn-north-1":
			instanceID = "i-china-node"
		}
		payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
			AccountID: "123456789012", InstanceID: instanceID, Region: region, AvailabilityZone: region + "a", ImageID: "ami-123",
		}))
		result, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
		require.NoError(t, err)
		require.Contains(t, result.AgentID, region)
		partition := "aws"
		switch region {
		case "us-gov-west-1":
			partition = "aws-us-gov"
		case "cn-north-1":
			partition = "aws-cn"
		}
		require.NotEmpty(t, eksEvents[start:], "EKS membership must be checked for each node")
		for _, event := range eksEvents[start:] {
			require.True(t, strings.HasPrefix(event, partition+":"), "EKS request %q used the wrong partition", event)
		}
		switch region {
		case "us-gov-west-1":
			foundProfileRole := false
			for _, selector := range result.Selectors {
				foundProfileRole = foundProfileRole || selector.Value == "iamrole:arn:aws-us-gov:iam::123456789012:role/profile-reader"
			}
			require.True(t, foundProfileRole, "profile lookup must use the node's partition client")
		case "cn-north-1":
			foundProfileRole := false
			for _, selector := range result.Selectors {
				foundProfileRole = foundProfileRole || selector.Value == "iamrole:arn:aws-cn:iam::123456789012:role/profile-reader"
			}
			require.True(t, foundProfileRole, "China profile lookup must use the node's partition client")
		}
	}
	require.Equal(t, []string{"aws:COMMERCIAL", "aws-us-gov:GOVERNMENT", "aws-cn:CHINA"}, selected)
}

func TestMultiPartitionOrganizationRegion(t *testing.T) {
	for _, tc := range []struct{ partition, region string }{
		{"aws-us-gov", "us-gov-west-1"},
		{"aws-cn", "cn-north-1"},
	} {
		t.Run(tc.partition, func(t *testing.T) {
			testOrganizationRegion(t, tc.partition, tc.region)
		})
	}
}

func testOrganizationRegion(t *testing.T, partition, region string) {
	certificate := generateCertificate(t, testAWSCAKey)
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return certificate, nil
	}
	var regions, partitions, orgRoles []string
	attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, region, _, orgRole string) (Client, error) {
		regions = append(regions, region)
		partitions = append(partitions, config.Partition)
		orgRoles = append(orgRoles, orgRole)
		return newFakeClient(), nil
	})
	var configureErr error
	plugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(attestor), plugin,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(fmt.Sprintf(`skip_block_device = true
disable_instance_profile_selectors = true
verify_organization = { management_account_id = "12345" assume_org_role = "org-reader" management_account_region = %q }
partition_credentials {
    aws { access_key_id = "COMMERCIAL" secret_access_key = "secret" }
    %s { access_key_id = "OTHER" secret_access_key = "secret" }
}`, region, partition)),
	)
	require.NoError(t, configureErr)
	payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
		AccountID: testAccountID, InstanceID: testInstance, Region: "us-east-1", AvailabilityZone: "us-east-1a", ImageID: "ami-123",
	}))
	_, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
	require.NoError(t, err)
	require.Equal(t, []string{region, "us-east-1"}, regions)
	require.Equal(t, []string{partition, "aws"}, partitions)
	require.Equal(t, "arn:"+partition+":iam::12345:role/org-reader", orgRoles[0])
}

func TestPartitionCredentialsWebIdentity(t *testing.T) {
	var stsCalls, roleCalls, ec2Calls int
	var rejectAccountRole atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		values, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		switch values.Get("Action") {
		case "AssumeRoleWithWebIdentity":
			stsCalls++
			require.Equal(t, "arn:aws-us-gov:iam::123456789012:role/base", values.Get("RoleArn"))
			if values.Get("WebIdentityToken") == "rejected-token" {
				http.Error(w, "invalid web identity token", http.StatusForbidden)
				return
			}
			require.Equal(t, "projected-token", values.Get("WebIdentityToken"))
			_, _ = io.WriteString(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIATEST</AccessKeyId><SecretAccessKey>testsecret</SecretAccessKey><SessionToken>sessiontoken</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
		case "AssumeRole":
			roleCalls++
			if rejectAccountRole.Load() {
				http.Error(w, "account role denied", http.StatusForbidden)
				return
			}
			require.Equal(t, "arn:aws-us-gov:iam::123456789012:role/node-reader", values.Get("RoleArn"))
			require.Contains(t, r.Header.Get("Authorization"), "ASIATEST")
			_, _ = io.WriteString(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAACCOUNT</AccessKeyId><SecretAccessKey>accountsecret</SecretAccessKey><SessionToken>accounttoken</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
		case "DescribeInstances":
			ec2Calls++
			require.True(t, strings.Contains(r.Header.Get("Authorization"), "ASIAACCOUNT"))
			_, _ = io.WriteString(w, `<DescribeInstancesResponse><requestId>test</requestId><reservationSet></reservationSet></DescribeInstancesResponse>`)
		default:
			t.Errorf("unexpected AWS action %q", values.Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	t.Setenv("AWS_ENDPOINT_URL_EC2", server.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("projected-token"), 0600))
	configuration := func(path string) string {
		return fmt.Sprintf(`partition_credentials {
	  aws-us-gov {
	    web_identity_role_arn = "arn:aws-us-gov:iam::123456789012:role/base"
	    web_identity_token_file = %q
	    assume_role = "node-reader"
	  }
}`, path)
	}

	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	var configureErr error
	plugintest.Load(t, builtin(attestor), nil,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(configuration(tokenPath)),
	)
	require.NoError(t, configureErr)
	client, err := attestor.clients.getClient(context.Background(), "us-gov-west-1", "123456789012")
	require.NoError(t, err)
	_, err = client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
	require.NoError(t, err)
	require.Equal(t, 1, stsCalls)
	require.Equal(t, 1, roleCalls)
	require.Equal(t, 1, ec2Calls)
	rejectAccountRole.Store(true)
	roleFailureAttestor := New()
	roleFailureAttestor.hooks.getenv = func(string) string { return "" }
	roleFailureAttestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return generateCertificate(t, testAWSCAKey), nil
	}
	var roleFailureConfigureErr error
	roleFailurePlugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(roleFailureAttestor), roleFailurePlugin,
		plugintest.CaptureConfigureError(&roleFailureConfigureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(configuration(tokenPath)),
	)
	require.NoError(t, roleFailureConfigureErr)
	rolePayload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
		AccountID: "123456789012", InstanceID: testInstance, Region: "us-gov-west-1", AvailabilityZone: "us-gov-west-1a", ImageID: "ami-123",
	}))
	_, err = roleFailurePlugin.Attest(context.Background(), rolePayload, expectNoChallenge)
	require.Error(t, err, "an account-role exchange failure must not use other credentials")
	require.Greater(t, roleCalls, 1)
	require.Equal(t, 1, ec2Calls, "account-role failure must not reach EC2 through ambient fallback")
	rejectedPath := filepath.Join(t.TempDir(), "rejected-token")
	require.NoError(t, os.WriteFile(rejectedPath, []byte("rejected-token"), 0600))
	failureAttestor := New()
	failureAttestor.hooks.getenv = func(string) string { return "" }
	failureAttestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return generateCertificate(t, testAWSCAKey), nil
	}
	var failureConfigureErr error
	failurePlugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(failureAttestor), failurePlugin,
		plugintest.CaptureConfigureError(&failureConfigureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(configuration(rejectedPath)),
	)
	if failureConfigureErr == nil {
		payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
			AccountID: "123456789012", InstanceID: testInstance, Region: "us-gov-west-1", AvailabilityZone: "us-gov-west-1a", ImageID: "ami-123",
		}))
		_, err := failurePlugin.Attest(context.Background(), payload, expectNoChallenge)
		require.Error(t, err, "a rejected web identity exchange must not fall back to ambient credentials")
		require.Equal(t, 1, ec2Calls, "rejected credentials must not reach EC2 through ambient fallback")
	}
}

func TestPartitionCredentialsUnavailableTokenFile(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "unexpected AWS request", http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	t.Setenv("AWS_ENDPOINT_URL_EC2", server.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	tokenPath := filepath.Join(t.TempDir(), "projected-token")

	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return generateCertificate(t, testAWSCAKey), nil
	}
	var configureErr error
	plugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(attestor), plugin,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(fmt.Sprintf(`partition_credentials {
    aws { access_key_id = "COMMERCIAL" secret_access_key = "secret" }
    aws-us-gov { web_identity_role_arn = "arn:aws-us-gov:iam::123456789012:role/base" web_identity_token_file = %q }
}`, tokenPath)),
	)
	if configureErr == nil {
		payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
			AccountID: "123456789012", InstanceID: testInstance, Region: "us-gov-west-1", AvailabilityZone: "us-gov-west-1a", ImageID: "ami-123",
		}))
		_, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
		require.Error(t, err, "an unavailable token file must fail attestation")
	}
	mu.Lock()
	defer mu.Unlock()
	require.Zero(t, requests, "missing web identity must not use ambient or another partition's credentials")
}

func TestPartitionCredentialsWebIdentityPartitions(t *testing.T) {
	for _, tc := range []struct{ partition, region string }{
		{"aws", "us-east-1"},
		{"aws-cn", "cn-north-1"},
	} {
		t.Run(tc.partition, func(t *testing.T) {
			testPartitionWebIdentity(t, tc.partition, tc.region)
		})
	}
}

func testPartitionWebIdentity(t *testing.T, partition, region string) {
	type request struct {
		action, role, token, authorization string
	}
	var requestMu sync.Mutex
	var requests []request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		action := values.Get("Action")
		requestMu.Lock()
		requests = append(requests, request{action, values.Get("RoleArn"), values.Get("WebIdentityToken"), r.Header.Get("Authorization")})
		requestMu.Unlock()
		switch action {
		case "AssumeRoleWithWebIdentity":
			_, _ = io.WriteString(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAWEBPARTITION</AccessKeyId><SecretAccessKey>testsecret</SecretAccessKey><SessionToken>sessiontoken</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
		case "DescribeInstances":
			_, _ = io.WriteString(w, `<DescribeInstancesResponse><requestId>test</requestId><reservationSet></reservationSet></DescribeInstancesResponse>`)
		default:
			http.Error(w, "unexpected AWS action", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	t.Setenv("AWS_ENDPOINT_URL_EC2", server.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	tokenPath := filepath.Join(t.TempDir(), "projected-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("projected-token"), 0600))
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	var configureErr error
	plugintest.Load(t, builtin(attestor), nil,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(fmt.Sprintf(`partition_credentials { %s { web_identity_role_arn = "arn:%s:iam::123456789012:role/base" web_identity_token_file = %q } }`, partition, partition, tokenPath)),
	)
	require.NoError(t, configureErr)
	client, err := attestor.clients.getClient(context.Background(), region, "123456789012")
	require.NoError(t, err)
	_, err = client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
	require.NoError(t, err)
	requestMu.Lock()
	observed := append([]request(nil), requests...)
	requestMu.Unlock()
	var stsSeen, ec2Seen bool
	for _, call := range observed {
		switch call.action {
		case "AssumeRoleWithWebIdentity":
			stsSeen = true
			require.Equal(t, "arn:"+partition+":iam::123456789012:role/base", call.role)
			require.Equal(t, "projected-token", call.token)
		case "DescribeInstances":
			ec2Seen = true
			require.Contains(t, call.authorization, "Credential=ASIAWEBPARTITION/")
		default:
			t.Errorf("unexpected AWS action %q", call.action)
		}
	}
	require.True(t, stsSeen)
	require.True(t, ec2Seen)
}

func TestPartitionCredentialsChinaAndLegacy(t *testing.T) {
	attestor := New()
	attestor.hooks.getenv = func(string) string { return "" }
	attestor.hooks.getAWSCACertificate = func(string, PublicKeyType) (*x509.Certificate, error) {
		return generateCertificate(t, testAWSCAKey), nil
	}
	var partitions, roles, keys []string
	attestor.clients = newClientsCache(func(_ context.Context, config *SessionConfig, _ string, role, _ string) (Client, error) {
		partitions = append(partitions, config.Partition)
		roles = append(roles, role)
		keys = append(keys, config.AccessKeyID)
		return newFakeClient(), nil
	})
	var configureErr error
	plugin := new(nodeattestor.V1)
	plugintest.Load(t, builtin(attestor), plugin,
		plugintest.CaptureConfigureError(&configureErr),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(`partition_credentials { aws-cn { access_key_id = "CHINA" secret_access_key = "secret" assume_role = "reader" } }`),
	)
	require.NoError(t, configureErr)
	_, err := attestor.clients.getClient(context.Background(), "cn-north-1", "123456789012")
	require.NoError(t, err)
	require.Equal(t, "aws-cn", partitions[0])
	require.Equal(t, "arn:aws-cn:iam::123456789012:role/reader", roles[0])

	_, err = attestor.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration: `partition = "aws-us-gov"
access_key_id = "LEGACY"
secret_access_key = "secret"
assume_role = "reader"`,
	})
	require.NoError(t, err)
	_, err = attestor.clients.getClient(context.Background(), "us-gov-east-1", "123456789012")
	require.NoError(t, err)
	require.Equal(t, "aws-us-gov", partitions[1])
	require.Equal(t, "arn:aws-us-gov:iam::123456789012:role/reader", roles[1])
	payload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
		AccountID: "123456789012", InstanceID: testInstance, Region: "us-gov-east-1", AvailabilityZone: "us-gov-east-1a", ImageID: "ami-123",
	}))
	result, err := plugin.Attest(context.Background(), payload, expectNoChallenge)
	require.NoError(t, err)
	require.Contains(t, result.AgentID, "us-gov-east-1")

	_, err = attestor.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration: `skip_block_device = true
validate_eks_cluster_membership = { eks_cluster_names = ["test-cluster"] }`,
	})
	require.NoError(t, err)
	defaultPayload := toJSON(t, buildAttestationDataRSA2048SignatureWithDoc(t, imds.InstanceIdentityDocument{
		AccountID: "123456789012", InstanceID: testInstance, Region: "us-east-1", AvailabilityZone: "us-east-1a", ImageID: "ami-123",
	}))
	result, err = plugin.Attest(context.Background(), defaultPayload, expectNoChallenge)
	require.NoError(t, err, "the legacy default commercial mode must retain optional EKS validation")
	require.Contains(t, result.AgentID, "us-east-1")
	require.Equal(t, "aws", partitions[2])
	require.Empty(t, roles[2])
	require.Empty(t, keys[2])

	_, err = attestor.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  `partition_credentials { aws {} }`,
	})
	require.NoError(t, err)
	_, err = attestor.clients.getClient(context.Background(), "us-west-2", "123456789012")
	require.NoError(t, err, "an empty partition block must retain the ambient AWS credential chain")
	require.Equal(t, "aws", partitions[3])
	require.Empty(t, roles[3])
	require.Empty(t, keys[3])
}

func TestAmbientPartitionCredentialsSignRequests(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	for _, tc := range []struct {
		name, config, key, region, otherRegion string
	}{
		{"commercial empty block", `partition_credentials { aws {} }`, "AMBIENT", "us-east-1", "cn-north-1"},
		{"China empty block", `partition_credentials { aws-cn {} }`, "AMBIENT", "cn-north-1", "us-east-1"},
		{"GovCloud empty block", `partition_credentials { aws-us-gov {} }`, "AMBIENT", "us-gov-west-1", "us-east-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authorizations := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authorizations <- r.Header.Get("Authorization")
				_, _ = io.WriteString(w, `<DescribeInstancesResponse><requestId>test</requestId><reservationSet></reservationSet></DescribeInstancesResponse>`)
			}))
			defer server.Close()
			t.Setenv("AWS_ENDPOINT_URL_EC2", server.URL)
			attestor := New()
			attestor.hooks.getenv = func(string) string { return "" }
			var configureErr error
			plugintest.Load(t, builtin(attestor), nil,
				plugintest.CaptureConfigureError(&configureErr),
				plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
				plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
				plugintest.Configure(tc.config),
			)
			require.NoError(t, configureErr)
			client, err := attestor.clients.getClient(context.Background(), tc.region, "123456789012")
			require.NoError(t, err)
			_, err = client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
			require.NoError(t, err)
			require.Contains(t, <-authorizations, "Credential="+tc.key+"/")
			_, err = attestor.clients.getClient(context.Background(), tc.otherRegion, "123456789012")
			require.Error(t, err, "an empty partition entry must not grant access to another partition")
		})
	}
}

func TestPartitionCredentialsRejectAmbiguity(t *testing.T) {
	cases := []string{
		`partition_credentials { aws { access_key_id = "A" secret_access_key = "B" } aws { access_key_id = "C" secret_access_key = "D" } }`,
		`partition_credentials { aws-cn {} aws-cn {} }`,
		`partition_credentials { aws-us-gov {} aws-us-gov {} }`,
		`partition_credentials { unsupported { access_key_id = "A" secret_access_key = "B" } }`,
		`partition_credentials { aws { access_key_id = "A" } }`,
		`partition_credentials { aws { secret_access_key = "B" } }`,
		`partition_credentials { aws-cn { access_key_id = "A" } }`,
		`partition_credentials { aws { web_identity_role_arn = "arn:aws:iam::123456789012:role/base" } }`,
		`partition_credentials { aws { web_identity_token_file = "/token" } }`,
		`partition_credentials { aws-us-gov { web_identity_token_file = "/token" } }`,
		`partition_credentials { aws { access_key_id = "A" secret_access_key = "B" web_identity_role_arn = "arn:aws:iam::123456789012:role/base" web_identity_token_file = "/token" } }`,
		`partition_credentials { aws { access_key_id = "A" web_identity_role_arn = "arn:aws:iam::123456789012:role/base" web_identity_token_file = "/token" } }`,
		`partition_credentials { aws { secret_access_key = "B" web_identity_role_arn = "arn:aws:iam::123456789012:role/base" web_identity_token_file = "/token" } }`,
		`partition_credentials { aws { access_key_id = "A" secret_access_key = "B" web_identity_role_arn = "arn:aws:iam::123456789012:role/base" } }`,
		`partition_credentials { aws { access_key_id = "A" secret_access_key = "B" web_identity_token_file = "/token" } }`,
		`partition_credentials { aws { web_identity_role_arn = "arn:aws-us-gov:iam::123456789012:role/base" web_identity_token_file = "/token" } }`,
		`partition_credentials { aws-cn { web_identity_role_arn = "arn:aws:iam::123456789012:role/base" web_identity_token_file = "/token" } }`,
		`partition_credentials { aws-us-gov { web_identity_role_arn = "arn:aws-cn:iam::123456789012:role/base" web_identity_token_file = "/token" } }`,
		`partition = "aws" partition_credentials { aws { access_key_id = "A" secret_access_key = "B" } }`,
		`access_key_id = "A" secret_access_key = "B" partition_credentials { aws { access_key_id = "C" secret_access_key = "D" } }`,
		`assume_role = "reader" partition_credentials { aws { access_key_id = "A" secret_access_key = "B" } }`,
		`web_identity_role_arn = "arn:aws:iam::123456789012:role/base" web_identity_token_file = "/token"`,
	}
	for _, source := range cases {
		t.Run(source, func(t *testing.T) {
			attestor := New()
			attestor.hooks.getenv = func(string) string { return "" }
			var configureErr error
			plugintest.Load(t, builtin(attestor), nil,
				plugintest.CaptureConfigureError(&configureErr),
				plugintest.HostServices(agentstorev1.AgentStoreServiceServer(fakeagentstore.New())),
				plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
				plugintest.Configure(source),
			)
			require.Error(t, configureErr)
		})
	}
}
