package gcp

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	defaultIdentityTokenHost     = "metadata.google.internal"
	identityTokenURLPathTemplate = "/computeMetadata/v1/instance/service-accounts/%s/identity"
	identityTokenAudience        = "spire-gcp-node-attestor" //nolint: gosec // false positive
	defaultServiceAccount        = "default"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IITAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(gcp.PluginName, nodeattestor.PluginServer(p))
}

// IITAttestorPlugin implements GCP nodeattestation in the agent.
type IITAttestorPlugin struct {
	mtx    sync.RWMutex
	config *IITAttestorConfig
}

// IITAttestorConfig configures a IITAttestorPlugin.
type IITAttestorConfig struct {
	trustDomain       string
	IdentityTokenHost string `hcl:"identity_token_host"`
	ServiceAccount    string `hcl:"service_account"`
}

// NewIITAttestorPlugin creates a new IITAttestorPlugin.
func New() *IITAttestorPlugin {
	return &IITAttestorPlugin{}
}

// FetchAttestationData fetches attestation data from the GCP metadata server and sends an attestation response
// on given stream.
func (p *IITAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	identityToken, err := retrieveInstanceIdentityToken(identityTokenURL(c.IdentityTokenHost, c.ServiceAccount))
	if err != nil {
		return newErrorf("unable to retrieve valid identity token: %v", err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: gcp.PluginName,
			Data: identityToken,
		},
	})
}

func (p *IITAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &IITAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, newErrorf("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, newError("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, newError("trust_domain is required")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	if config.ServiceAccount == "" {
		config.ServiceAccount = defaultServiceAccount
	}

	if config.IdentityTokenHost == "" {
		config.IdentityTokenHost = defaultIdentityTokenHost
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *IITAttestorPlugin) getConfig() (*IITAttestorConfig, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.config == nil {
		return nil, newError("not configured")
	}
	return p.config, nil
}

// identityTokenURL creates the URL to find an instance identity document given the
// host of the GCP metadata server and the service account the instance is running as.
func identityTokenURL(host, serviceAccount string) string {
	query := url.Values{}
	query.Set("audience", identityTokenAudience)
	query.Set("format", "full")
	url := &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     fmt.Sprintf(identityTokenURLPathTemplate, serviceAccount),
		RawQuery: query.Encode(),
	}
	return url.String()
}

func retrieveInstanceIdentityToken(url string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
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

func newError(msg string) error {
	return errors.New("gcp-iit: " + msg)
}

func newErrorf(format string, args ...interface{}) error {
	return fmt.Errorf("gcp-iit: "+format, args...)
}
