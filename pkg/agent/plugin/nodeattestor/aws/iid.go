package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultIdentityDocumentURL  = "http://169.254.169.254/latest/dynamic/instance-identity/document"
	defaultIdentitySignatureURL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"

	docPath = "instance-identity/document"
	sigPath = "instance-identity/signature"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(aws.PluginName, nodeattestor.PluginServer(p))
}

// IIDAttestorConfig configures a IIDAttestorPlugin.
type IIDAttestorConfig struct {
	EC2MetadataEndpoint            string `hcl:"ec2_metadata_endpoint"`
	DeprecatedIdentityDocumentURL  string `hcl:"identity_document_url"`
	DeprecatedIdentitySignatureURL string `hcl:"identity_signature_url"`
}

// IIDAttestorPlugin implements aws nodeattestation in the agent.
type IIDAttestorPlugin struct {
	log    hclog.Logger
	config *IIDAttestorConfig
	mtx    sync.RWMutex
}

// New creates a new IIDAttestorPlugin.
func New() *IIDAttestorPlugin {
	return &IIDAttestorPlugin{}
}

func (p *IIDAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// FetchAttestationData fetches attestation data from the aws metadata server and sends an attestation response
// on given stream.
func (p *IIDAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	var attestationData *aws.IIDAttestationData

	if c.isLegacyConfig() {
		// Legacy configuration
		attestationData, err = legacyFetch(c)
		if err != nil {
			return err
		}
	} else {
		attestationData, err = fetchMetadata(c.EC2MetadataEndpoint)
		if err != nil {
			return err
		}
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

func fetchMetadata(endpoint string) (*aws.IIDAttestationData, error) {
	awsCfg := awssdk.NewConfig()
	if endpoint != "" {
		awsCfg.WithEndpoint(endpoint)
	}
	newSession, err := session.NewSession(awsCfg)
	if err != nil {
		return nil, err
	}

	client := ec2metadata.New(newSession)

	doc, err := client.GetDynamicData(docPath)
	if err != nil {
		return nil, err
	}

	sig, err := client.GetDynamicData(sigPath)
	if err != nil {
		return nil, err
	}

	return &aws.IIDAttestationData{
		Document:  doc,
		Signature: sig,
	}, nil
}

func legacyFetch(c *IIDAttestorConfig) (*aws.IIDAttestationData, error) {
	docBytes, err := httpGetBytes(c.DeprecatedIdentityDocumentURL)
	if err != nil {
		return nil, aws.AttestationStepError("retrieving the IID from AWS", err)
	}
	sigBytes, err := httpGetBytes(c.DeprecatedIdentitySignatureURL)
	if err != nil {
		return nil, aws.AttestationStepError("retrieving the IID signature from AWS", err)
	}
	return &aws.IIDAttestationData{
		Document:  string(docBytes),
		Signature: string(sigBytes),
	}, nil
}

// Configure configures the IIDAttestorPlugin.
func (p *IIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.EC2MetadataEndpoint != "" {
		if config.DeprecatedIdentityDocumentURL != "" {
			p.log.Warn("Deprecated configuration identity_document_url ignored because ec2_metadata_endpoint is set")
		}

		if config.DeprecatedIdentitySignatureURL != "" {
			p.log.Warn("Deprecated configuration identity_signature_url ignored because ec2_metadata_endpoint is set")
		}
	} else {
		if config.DeprecatedIdentityDocumentURL != "" {
			p.log.Warn("configuration identity_document_url is deprecated, please use ec2_metadata_endpoint instead")
		}

		if config.DeprecatedIdentitySignatureURL != "" {
			p.log.Warn("configuration identity_signature_url is deprecated, please use ec2_metadata_endpoint instead")
		}
	}

	// If we have a legacy config, ensure both have a value
	if config.isLegacyConfig() {
		if config.DeprecatedIdentityDocumentURL == "" {
			config.DeprecatedIdentityDocumentURL = defaultIdentityDocumentURL
		}

		if config.DeprecatedIdentitySignatureURL == "" {
			config.DeprecatedIdentitySignatureURL = defaultIdentitySignatureURL
		}
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

// isLegacyConfig returns true if either deprecated configurable is set
func (c *IIDAttestorConfig) isLegacyConfig() bool {
	return c.EC2MetadataEndpoint == "" &&
		(c.DeprecatedIdentitySignatureURL != "" || c.DeprecatedIdentityDocumentURL != "")
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
