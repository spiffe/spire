package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"

	"errors"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	defaultIdentityDocumentHost  = "169.254.169.254"
	defaultIdentityDocumentPath  = "/latest/dynamic/instance-identity/document"
	defaultIdentitySignatureHost = "169.254.169.254"
	defaultIdentitySignaturePath = "/latest/dynamic/instance-identity/signature"
)

// IIDAttestorConfig configures a IIDAttestorPlugin.
type IIDAttestorConfig struct {
	IdentityDocumentURL  string `hcl:"identity_document_url"`
	IdentitySignatureURL string `hcl:"identity_signature_url"`
	AgentPathTemplate    string `hcl:"agent_path_template"`
	trustDomain          string
	pathTemplate         *template.Template
}

// IIDAttestorPlugin implements aws nodeattestation in the agent.
type IIDAttestorPlugin struct {
	config *IIDAttestorConfig
	mtx    sync.RWMutex
}

// NewIIDPlugin creates a new IIDAttestorPlugin.
func NewIIDPlugin() *IIDAttestorPlugin {
	return &IIDAttestorPlugin{}
}

// FetchAttestationData fetches attestation data from the aws metadata server and sends an attestation response
// on given stream.
func (p *IIDAttestorPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	docBytes, err := httpGetBytes(identityURL(c.IdentityDocumentURL))
	if err != nil {
		err = aws.AttestationStepError("retrieving the IID from AWS", err)
		return err
	}

	var doc aws.InstanceIdentityDocument
	err = json.Unmarshal(docBytes, &doc)
	if err != nil {
		err = aws.AttestationStepError("unmarshaling the IID", err)
		return err
	}

	sigBytes, err := httpGetBytes(identityURL(c.IdentitySignatureURL))
	if err != nil {
		err = aws.AttestationStepError("retrieving the IID signature from AWS", err)
		return err
	}

	attestationData := aws.IIDAttestationData{
		Document:  string(docBytes),
		Signature: string(sigBytes),
	}

	respData, err := json.Marshal(attestationData)
	if err != nil {
		err = aws.AttestationStepError("marshaling the attested data", err)
		return err
	}

	// FIXME: NA should be the one dictating type of this message
	// Change the proto to just take plain byte here
	data := &common.AttestationData{
		Type: aws.PluginName,
		Data: respData,
	}

	spiffeID, err := aws.MakeSpiffeID(c.trustDomain, c.pathTemplate, doc)
	if err != nil {
		return fmt.Errorf("failed to create spiffe ID: %v", err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: data,
		SpiffeId:        spiffeID.String(),
	})
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	if req.GlobalConfig == nil {
		err := errors.New("global configuration is required")
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	if req.GlobalConfig.TrustDomain == "" {
		err := errors.New("global configuration missing trust domain")
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	// Set local vars from config struct
	config.trustDomain = req.GlobalConfig.TrustDomain

	if config.IdentityDocumentURL == "" {
		config.IdentityDocumentURL = defaultIdentityDocumentHost + defaultIdentityDocumentPath
	}

	if config.IdentitySignatureURL == "" {
		config.IdentitySignatureURL = defaultIdentitySignatureHost + defaultIdentitySignaturePath
	}

	config.pathTemplate = aws.DefaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		tmpl, err := template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent svid template: %q", config.AgentPathTemplate)
		}
		config.pathTemplate = tmpl
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return resp, nil
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

func identityURL(rawurl string) string {
	spliturl := strings.SplitN(rawurl, "/", 2)
	url := &url.URL{
		Scheme: "http",
		Host:   spliturl[0],
		Path:   spliturl[1],
	}
	return url.String()
}

func httpGetBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
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
