package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"errors"

	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	defaultIdentityDocumentURL  = "http://169.254.169.254/latest/dynamic/instance-identity/document"
	defaultIdentitySignatureURL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(aws.PluginName, nodeattestor.PluginServer(p))
}

// IIDAttestorConfig configures a IIDAttestorPlugin.
type IIDAttestorConfig struct {
	IdentityDocumentURL  string `hcl:"identity_document_url"`
	IdentitySignatureURL string `hcl:"identity_signature_url"`
	trustDomain          string
}

// IIDAttestorPlugin implements aws nodeattestation in the agent.
type IIDAttestorPlugin struct {
	config *IIDAttestorConfig
	mtx    sync.RWMutex
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	return &IIDAttestorPlugin{}
}

// FetchAttestationData fetches attestation data from the aws metadata server and sends an attestation response
// on given stream.
func (p *IIDAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	docBytes, err := httpGetBytes(c.IdentityDocumentURL)
	if err != nil {
		return aws.AttestationStepError("retrieving the IID from AWS", err)
	}

	sigBytes, err := httpGetBytes(c.IdentitySignatureURL)
	if err != nil {
		return aws.AttestationStepError("retrieving the IID signature from AWS", err)
	}

	attestationData := aws.IIDAttestationData{
		Document:  string(docBytes),
		Signature: string(sigBytes),
	}

	respData, err := json.Marshal(attestationData)
	if err != nil {
		return aws.AttestationStepError("marshaling the attested data", err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: aws.PluginName,
			Data: respData,
		},
	})
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, status.Error(codes.InvalidArgument, "global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "global configuration missing trust domain")
	}
	// Set local vars from config struct
	config.trustDomain = req.GlobalConfig.TrustDomain

	if config.IdentityDocumentURL == "" {
		config.IdentityDocumentURL = defaultIdentityDocumentURL
	}

	if config.IdentitySignatureURL == "" {
		config.IdentitySignatureURL = defaultIdentitySignatureURL
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*IIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *IIDAttestorPlugin) getConfig() (*IIDAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, errors.New("not configured")
	}
	return p.config, nil
}

func httpGetBytes(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint: gosec // URL is provided via explicit configuration
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
