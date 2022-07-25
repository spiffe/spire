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

type MSIAttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *MSIAttestorConfig

	hooks struct {
		fetchMSIToken func(context.Context, azure.HTTPClient, string) (string, error)
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
	token, err := p.hooks.fetchMSIToken(stream.Context(), http.DefaultClient, config.ResourceID)
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

func (p *MSIAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(MSIAttestorConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.ResourceID == "" {
		config.ResourceID = azure.DefaultMSIResourceID
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *MSIAttestorPlugin) getConfig() (*MSIAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *MSIAttestorPlugin) setConfig(config *MSIAttestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}
