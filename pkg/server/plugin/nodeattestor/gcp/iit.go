package gcp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	jwt "github.com/dgrijalva/jwt-go"
	cgcp "github.com/spiffe/spire/pkg/common/plugin/gcp"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	pluginName    = "gcp_iit"
	audience      = "spire-gcp-node-attestor"
	googleCertURL = "https://www.googleapis.com/oauth2/v1/certs"
)

type tokenKeyRetriever interface {
	retrieveKey(token *jwt.Token) (interface{}, error)
}

type googlePublicKeyRetriever struct {
	certificates map[string]*x509.Certificate
	expirey      int64
	mtx          *sync.Mutex
}

func (r *googlePublicKeyRetriever) retrieveKey(token *jwt.Token) (interface{}, error) {
	if token.Header["kid"] == nil {
		return nil, fmt.Errorf("Missing kid in identityToken header. Cannot verify token")
	}
	kid := token.Header["kid"].(string)
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}

	if r.expirey == 0 || time.Now().Unix() > r.expirey {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		err := r.downloadCertificates()
		if err != nil {
			return nil, err
		}
	}
	return r.certificates[kid].PublicKey, nil
}

func (r *googlePublicKeyRetriever) downloadCertificates() error {
	resp, err := http.Get(googleCertURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var data map[string]string
	err = json.Unmarshal(bytes, &data)

	for k, v := range data {
		block, _ := pem.Decode([]byte(v))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		r.certificates[k] = cert
	}
	t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 MST", resp.Header["Expires"][0])
	r.expirey = t.Unix()
	return nil
}

type IITAttestorConfig struct {
	TrustDomain        string   `hcl:"trust_domain"`
	ProjectIDWhitelist []string `hcl:"projectid_whitelist`
}

type IITAttestorPlugin struct {
	trustDomain        string
	projectIDWhitelist []string
	tokenKeyRetriever  tokenKeyRetriever
	mtx                *sync.Mutex
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

func (p *IITAttestorPlugin) Attest(ctx context.Context, req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	if req == nil || req.GetAttestedData() == nil {
		err := cgcp.AttestationStepError("retrieving the attested data", fmt.Errorf("AttestRequest or attestedData is nil"))
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	identityToken := &cgcp.IdentityToken{}
	_, err := jwt.ParseWithClaims(string(req.GetAttestedData().Data), identityToken, p.tokenKeyRetriever.retrieveKey)
	if err != nil {
		err = cgcp.AttestationStepError("parsing the identity token", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	if identityToken.Audience != audience {
		err = cgcp.AttestationStepError("Audience claim in the token doesn't match the expected audience", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	if req.AttestedBefore {
		err = cgcp.AttestationStepError("validation the InstanceID", fmt.Errorf("the InstanceID has been used and cannot be registered again"))
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	projectIDMatchesWhitelist := false
	for _, projectID := range p.projectIDWhitelist {
		if identityToken.Google.ComputeEngine.ProjectID == projectID {
			projectIDMatchesWhitelist = true
			break
		}
	}
	if !projectIDMatchesWhitelist {
		err = cgcp.AttestationStepError("validation of the ProjectID", fmt.Errorf("the projectID doen't match the projectID whitelist"))
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: p.spiffeID(identityToken.Google.ComputeEngine.ProjectID, identityToken.Google.ComputeEngine.InstanceID).String(),
	}
	return resp, nil

}

func (p *IITAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	config := &IITAttestorConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := fmt.Errorf("Error parsing GCP IID Attestor configuration %v", err)
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := fmt.Errorf("Error decoding GCP IID Attestor configuration: %v", err)
		return resp, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	if config.TrustDomain == "" {
		err := fmt.Errorf("Missing trust_domain configuration parameter")
		return resp, err
	}
	p.trustDomain = config.TrustDomain

	if config.ProjectIDWhitelist == nil || len(config.ProjectIDWhitelist) == 0 {
		err := fmt.Errorf("Missing domain_whitelist configuration parameter")
		return resp, err
	}
	p.projectIDWhitelist = config.ProjectIDWhitelist

	return resp, nil
}

func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewInstanceIdentityToken() nodeattestor.NodeAttestor {
	return &IITAttestorPlugin{
		mtx: &sync.Mutex{},
		tokenKeyRetriever: &googlePublicKeyRetriever{
			certificates: make(map[string]*x509.Certificate),
			mtx:          &sync.Mutex{},
		},
	}
}
