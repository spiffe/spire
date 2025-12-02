package azureimds

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "azure_imds"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *IMDSAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type IMDSAttestorConfig struct {
	// TenantDomain is the domain of the tenant in which the VM is running.
	TenantDomain string `hcl:"tenant_domain"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *IMDSAttestorConfig {
	newConfig := new(IMDSAttestorConfig)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.TenantDomain == "" {
		status.ReportError("tenant_domain is required")
	}

	return newConfig
}

type IMDSAttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *IMDSAttestorConfig

	hooks struct {
		fetchAttestedDocument func(azure.HTTPClient, string) (*azure.AttestedDocument, error)
		fetchComputeMetadata  func(azure.HTTPClient) (*azure.InstanceMetadata, error)
	}
}

func New() *IMDSAttestorPlugin {
	p := &IMDSAttestorPlugin{}
	p.hooks.fetchAttestedDocument = azure.FetchAttestedDocument
	p.hooks.fetchComputeMetadata = azure.FetchInstanceMetadata
	return p
}

func (p *IMDSAttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// send initial payload, this is just so we can receive a challenge containing the nonce
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("non_empty_payload"),
		},
	}); err != nil {
		return err
	}

	// receive challenge containing the nonce which we will use to fetch the attested document
	challenge, err := stream.Recv()
	if err != nil {
		return err
	}

	nonce := string(challenge.Challenge)

	// Get the attested document
	attestedDocument, err := p.hooks.fetchAttestedDocument(http.DefaultClient, nonce)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to fetch attested document: %v", err)
	}

	// Get the compute metadata
	computeMetadata, err := p.hooks.fetchComputeMetadata(http.DefaultClient)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to fetch compute metadata: %v", err)
	}

	md := azure.AgentUntrustedMetadata{
		AgentDomain: config.TenantDomain,
	}
	if computeMetadata.Compute.VMScaleSetName != "" {
		md.VMSSName = &computeMetadata.Compute.VMScaleSetName
	}

	payload, err := json.Marshal(azure.IMDSAttestationPayload{
		Document: *attestedDocument,
		Metadata: md,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal payload: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: payload,
		},
	})
}

func (p *IMDSAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *IMDSAttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *IMDSAttestorPlugin) getConfig() (*IMDSAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
