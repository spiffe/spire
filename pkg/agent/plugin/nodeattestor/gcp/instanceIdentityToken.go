package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	cgcp "github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	pluginName              = "gcp_instance_identity_token"
	defaultIdentityTokenURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
	queryParameters         = "?audience=%v&format=full"
)

type InstanceIdentityTokenAttestorConfig struct {
	TrustDomain      string `hcl:"trust_domain"`
	Audience         string `hcl:"audience"`
	IdentityTokenURL string `hcl:"identity_troken_url"`
}

type InstanceIdentityTokenAttestorPlugin struct {
	trustDomain      string
	audience         string
	identityTokenURL string

	mtx *sync.RWMutex
}

func (p *InstanceIdentityTokenAttestorPlugin) spiffeID(gcpAccountID string, gcpInstanceID string) *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, gcpAccountID, gcpInstanceID)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}
	return id
}

func httpGetBytes(url string) ([]byte, error) {
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

func (p *InstanceIdentityTokenAttestorPlugin) FetchAttestationData(ctx context.Context, req *nodeattestor.FetchAttestationDataRequest) (*nodeattestor.FetchAttestationDataResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	docBytes, err := httpGetBytes(fmt.Sprintf(p.identityTokenURL+queryParameters, p.audience))
	if err != nil {
		err = gcp.AttestationStepError("retrieving the Token from GCP", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	parts := strings.Split(string(docBytes), ".")
	iidAttestData := &cgcp.IIDAttestedData{}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		err = gcp.AttestationStepError(fmt.Sprintf("base64 decoding the IdentityToken header: %v", parts[0]), err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}
	iidAttestData.Header = string(header)
	token, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		err = gcp.AttestationStepError("base64 decoding the IdentityToken token", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}
	iidAttestData.Token = string(token)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		err = gcp.AttestationStepError("base64 decoding the IdentityToken signature", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}
	iidAttestData.Signature = signature

	var identityToken cgcp.IdentityToken
	err = json.Unmarshal([]byte(iidAttestData.Token), &identityToken)
	if err != nil {
		err = gcp.AttestationStepError(fmt.Sprintf("unmarshalling the IdentityToken %v", string(docBytes)), err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	respData, err := json.Marshal(iidAttestData)
	if err != nil {
		err = gcp.AttestationStepError("marshaling the attested data", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	data := &common.AttestedData{
		Type: pluginName,
		Data: respData,
	}

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: data,
		SpiffeId:     p.spiffeID(identityToken.Google.ComputeEngine.ProjectID, identityToken.Google.ComputeEngine.InstanceID).String(),
	}

	return resp, nil
}

func (p *InstanceIdentityTokenAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	resp := &spi.ConfigureResponse{}

	config := &InstanceIdentityTokenAttestorConfig{}
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

	if config.Audience == "" {
		err = fmt.Errorf("Missing audience configuration parameter")
		return nil, err
	}
	p.audience = config.Audience
	if config.IdentityTokenURL != "" {
		p.identityTokenURL = config.IdentityTokenURL
	} else {
		p.identityTokenURL = defaultIdentityTokenURL
	}

	return resp, nil
}

func (*InstanceIdentityTokenAttestorPlugin) GetPluginInfo(ctx context.Context,req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewInstanceIdentityToken() nodeattestor.NodeAttestor {
	return &InstanceIdentityTokenAttestorPlugin{
		mtx: &sync.RWMutex{},
	}
}
