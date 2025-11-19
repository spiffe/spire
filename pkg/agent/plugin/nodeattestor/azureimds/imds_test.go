package azureimds

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

var (
	streamBuilder = nodeattestortest.ServerStream(pluginName)
)

func TestIMDSAttestorPlugin(t *testing.T) {
	spiretest.Run(t, new(IMDSAttestorSuite))
}

type IMDSAttestorSuite struct {
	spiretest.Suite

	attestedDocument   *azure.AttestedDocument
	attestedDocErr     error
	computeMetadata    *azure.InstanceMetadata
	computeMetadataErr error
}

func (s *IMDSAttestorSuite) SetupTest() {
	s.attestedDocument = &azure.AttestedDocument{
		Encoding:  "base64",
		Signature: "signature",
	}
	s.attestedDocErr = nil
	s.computeMetadata = &azure.InstanceMetadata{
		Compute: azure.ComputeMetadata{
			Name:              "vm-name",
			SubscriptionID:    "subscription-id",
			ResourceGroupName: "resource-group",
		},
	}
	s.computeMetadataErr = nil
}

func (s *IMDSAttestorSuite) TestAidAttestationNotConfigured() {
	attestor := s.loadAttestor()

	err := attestor.Attest(context.Background(), streamBuilder.Build())
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "nodeattestor(azure_imds): not configured")
}

func (s *IMDSAttestorSuite) TestAidAttestationSuccess() {
	nonce := []byte("test-nonce")
	expectedPayload := []byte("non_empty_payload")

	attestor := s.loadAttestor(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`tenant_domain = "example.com"`),
	)

	// The plugin sends initial payload, then receives challenge, then sends challenge response
	stream := streamBuilder.
		ExpectThenChallenge(expectedPayload, nonce).
		ExpectAndBuild(s.makeExpectedChallengeResponse())

	err := attestor.Attest(context.Background(), stream)
	s.Require().NoError(err)
}

func (s *IMDSAttestorSuite) TestAidAttestationWithVMSS() {
	vmssName := "vmss-name"
	s.computeMetadata.Compute.VMScaleSetName = vmssName

	nonce := []byte("test-nonce")
	expectedPayload := []byte("non_empty_payload")

	attestor := s.loadAttestor(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`tenant_domain = "example.com"`),
	)

	stream := streamBuilder.
		ExpectThenChallenge(expectedPayload, nonce).
		ExpectAndBuild(s.makeExpectedChallengeResponse())

	err := attestor.Attest(context.Background(), stream)
	s.Require().NoError(err)
}

func (s *IMDSAttestorSuite) TestAidAttestationFailedToFetchAttestedDocument() {
	s.attestedDocErr = errors.New("fetch failed")

	nonce := []byte("test-nonce")
	expectedPayload := []byte("non_empty_payload")

	attestor := s.loadAttestor(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`tenant_domain = "example.com"`),
	)

	stream := streamBuilder.
		ExpectThenChallenge(expectedPayload, nonce).
		Build()

	err := attestor.Attest(context.Background(), stream)
	s.RequireGRPCStatus(err, codes.Internal, "nodeattestor(azure_imds): unable to fetch attested document: fetch failed")
}

func (s *IMDSAttestorSuite) TestAidAttestationFailedToFetchComputeMetadata() {
	s.computeMetadataErr = errors.New("metadata fetch failed")

	nonce := []byte("test-nonce")
	expectedPayload := []byte("non_empty_payload")

	attestor := s.loadAttestor(
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`tenant_domain = "example.com"`),
	)

	stream := streamBuilder.
		ExpectThenChallenge(expectedPayload, nonce).
		Build()

	err := attestor.Attest(context.Background(), stream)
	s.RequireGRPCStatus(err, codes.Internal, "nodeattestor(azure_imds): unable to fetch compute metadata: metadata fetch failed")
}

func (s *IMDSAttestorSuite) TestConfigure() {
	// malformed configuration
	var err error
	s.loadAttestor(
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure("blah"),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "unable to decode configuration")

	// missing tenant_domain
	s.loadAttestor(
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(""),
	)
	s.RequireGRPCStatusContains(err, codes.InvalidArgument, "tenant_domain is required")

	// success
	s.loadAttestor(
		plugintest.CaptureConfigureError(&err),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(`tenant_domain = "example.com"`),
	)
	s.Require().NoError(err)
}

func (s *IMDSAttestorSuite) TestValidate() {
	s.T().Run("valid configuration", func(t *testing.T) {
		attestor := New()

		resp, err := attestor.Validate(context.Background(), &configv1.ValidateRequest{
			CoreConfiguration: &configv1.CoreConfiguration{
				TrustDomain: "example.org",
			},
			HclConfiguration: `tenant_domain = "example.com"`,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Valid)
	})

	s.T().Run("invalid configuration - malformed HCL", func(t *testing.T) {
		attestor := New()

		resp, err := attestor.Validate(context.Background(), &configv1.ValidateRequest{
			CoreConfiguration: &configv1.CoreConfiguration{
				TrustDomain: "example.org",
			},
			HclConfiguration: "blah",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Valid)
		require.NotEmpty(t, resp.Notes)
		notesStr := strings.Join(resp.Notes, " ")
		require.Contains(t, notesStr, "unable to decode configuration")
	})

	s.T().Run("invalid configuration - missing tenant_domain", func(t *testing.T) {
		attestor := New()

		resp, err := attestor.Validate(context.Background(), &configv1.ValidateRequest{
			CoreConfiguration: &configv1.CoreConfiguration{
				TrustDomain: "example.org",
			},
			HclConfiguration: "",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Valid)
		require.NotEmpty(t, resp.Notes)
		notesStr := strings.Join(resp.Notes, " ")
		require.Contains(t, notesStr, "tenant_domain is required")
	})
}

func (s *IMDSAttestorSuite) loadAttestor(options ...plugintest.Option) nodeattestor.NodeAttestor {
	p := New()
	p.hooks.fetchAttestedDocument = func(httpClient azure.HTTPClient, nonce string) (*azure.AttestedDocument, error) {
		if httpClient != http.DefaultClient {
			return nil, errors.New("unexpected http client")
		}
		return s.attestedDocument, s.attestedDocErr
	}
	p.hooks.fetchComputeMetadata = func(httpClient azure.HTTPClient) (*azure.InstanceMetadata, error) {
		if httpClient != http.DefaultClient {
			return nil, errors.New("unexpected http client")
		}
		return s.computeMetadata, s.computeMetadataErr
	}

	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(p), attestor, options...)
	return attestor
}

func (s *IMDSAttestorSuite) makeExpectedChallengeResponse() []byte {
	md := azure.AgentUntrustedMetadata{
		AgentDomain: "example.com",
	}
	if s.computeMetadata.Compute.VMScaleSetName != "" {
		md.VMSSName = &s.computeMetadata.Compute.VMScaleSetName
	}

	payload := azure.IMDSAttestationPayload{
		Document: *s.attestedDocument,
		Metadata: md,
	}

	expectedResponse, err := json.Marshal(payload)
	s.Require().NoError(err)
	return expectedResponse
}
