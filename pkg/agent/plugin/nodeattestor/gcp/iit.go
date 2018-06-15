package gcp

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	cgcp "github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	pluginName       = "gcp_iit"
	identityTokenUrl = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=%v&format=full"
	audience         = "spire-gcp-node-attestor"
)

type IITAttestorConfig struct {
	TrustDomain string `hcl:"trust_domain"`
}

type IITAttestorPlugin struct {
	trustDomain string

	mtx *sync.RWMutex
}

func (p *IITAttestorPlugin) spiffeID(gcpAccountID string, gcpInstanceID string) *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, gcpAccountID, gcpInstanceID)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}
	return id
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
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (p *IITAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationData_PluginStream) error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	docBytes, err := retrieveInstanceIdentityToken(fmt.Sprintf(identityTokenUrl, audience))
	if err != nil {
		return gcp.AttestationStepError("retrieving the identity token", err)
	}

	resp, err := p.BuildAttestationResponse(docBytes)
	if err != nil {
		return err
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (p *IITAttestorPlugin) BuildAttestationResponse(identityTokenBytes []byte) (*nodeattestor.FetchAttestationDataResponse, error) {

	identityToken := &cgcp.IdentityToken{}
	_, err := jwt.ParseWithClaims(string(identityTokenBytes), identityToken, nil)
	if err != nil {
		_, ok := err.(*jwt.ValidationError) // we are ignoring validation error since we are not checking the signature on the client side
		if !ok {
			err = gcp.AttestationStepError("parsing the identity token", err)
			return &nodeattestor.FetchAttestationDataResponse{}, err
		}
	}

	if identityToken.Google == (cgcp.Google{}) {
		err = gcp.AttestationStepError("retrieving the claims of the identity token", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	data := &common.AttestationData{
		Type: pluginName,
		Data: identityTokenBytes,
	}

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestationData: data,
		SpiffeId:        p.spiffeID(identityToken.Google.ComputeEngine.ProjectID, identityToken.Google.ComputeEngine.InstanceID).String(),
	}
	return resp, nil
}

func (p *IITAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	resp := &spi.ConfigureResponse{}

	config := &IITAttestorConfig{}
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

	if config.TrustDomain == "" {
		err = fmt.Errorf("Missing trust_domain configuration parameter")
		return nil, err
	}
	p.trustDomain = config.TrustDomain

	return resp, nil
}

func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewIITPlugin() nodeattestor.NodeAttestorPlugin {
	return &IITAttestorPlugin{
		mtx: &sync.RWMutex{},
	}
}
