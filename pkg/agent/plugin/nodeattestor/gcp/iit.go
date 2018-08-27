package gcp

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	identityTokenURLHost  = "metadata"
	identityTokenURLPath  = "/computeMetadata/v1/instance/service-accounts/default/identity"
	identityTokenAudience = "spire-gcp-node-attestor"
)

type IITAttestorConfig struct {
}

type IITAttestorPlugin struct {
	tokenHost   string
	trustDomain string

	mtx    sync.RWMutex
	config *IITAttestorConfig
}

func identityTokenURL(host string) string {
	query := url.Values{}
	query.Set("audience", identityTokenAudience)
	query.Set("format", "full")
	url := &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     identityTokenURLPath,
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

func (p *IITAttestorPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) error {
	docBytes, err := retrieveInstanceIdentityToken(identityTokenURL(p.tokenHost))
	if err != nil {
		return newErrorf("unable to retrieve identity token: %v", err)
	}

	resp, err := p.buildAttestationResponse(p.trustDomain, docBytes)
	if err != nil {
		return err
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (p *IITAttestorPlugin) buildAttestationResponse(trustDomain string, identityTokenBytes []byte) (*nodeattestor.FetchAttestationDataResponse, error) {
	identityToken := &gcp.IdentityToken{}
	_, _, err := new(jwt.Parser).ParseUnverified(string(identityTokenBytes), identityToken)
	if err != nil {
		return nil, newErrorf("unable to parse identity token: %v", err)
	}

	if identityToken.Google == (gcp.Google{}) {
		return nil, newError("identity token is missing google claims")
	}

	data := &common.AttestationData{
		Type: gcp.PluginName,
		Data: identityTokenBytes,
	}

	spiffeID := gcp.MakeSpiffeID(trustDomain, identityToken.Google.ComputeEngine.ProjectID, identityToken.Google.ComputeEngine.InstanceID)

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestationData: data,
		SpiffeId:        spiffeID,
	}
	return resp, nil
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
	p.trustDomain = req.GlobalConfig.TrustDomain

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = config

	return &spi.ConfigureResponse{}, nil
}

func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewIITAttestorPlugin() *IITAttestorPlugin {
	return &IITAttestorPlugin{
		tokenHost: identityTokenURLHost,
	}
}

func newError(msg string) error {
	return errors.New("gcp-iit: " + msg)
}

func newErrorf(format string, args ...interface{}) error {
	return fmt.Errorf("gcp-iit: "+format, args...)
}
