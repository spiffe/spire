package azuremsi

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
	pluginName = "azure_msi"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *MSIAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type MSIAttestorConfig struct {
	// ResourceID assigned to the MSI token. This value is the intended
	// audience of the token, in other words, which service the token can be
	// used to authenticate with. Ideally deployments use the ID of an
	// application they registered with the active directory to limit the scope
	// of use of the token. A bogus value cannot be used; Azure makes sure the
	// resource ID is either an azure service ID or a registered app ID.
	ResourceID string `hcl:"resource_id"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *MSIAttestorConfig {
	newConfig := new(MSIAttestorConfig)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.ResourceID == "" {
		newConfig.ResourceID = azure.DefaultMSIResourceID
	}

	return newConfig
}

type MSIAttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *MSIAttestorConfig

	hooks struct {
		fetchMSIToken func(azure.HTTPClient, string) (string, error)
	}
}

func New() *MSIAttestorPlugin {
	p := &MSIAttestorPlugin{}
	p.hooks.fetchMSIToken = azure.FetchMSIToken
	return p
}

func (p *MSIAttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// Obtain an MSI token from the Azure Instance Metadata Service
	token, err := p.hooks.fetchMSIToken(http.DefaultClient, config.ResourceID)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to fetch token: %v", err)
	}

	payload, err := json.Marshal(azure.MSIAttestationData{
		Token: token,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal payload: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	})
}

func (p *MSIAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *MSIAttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *MSIAttestorPlugin) getConfig() (*MSIAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
