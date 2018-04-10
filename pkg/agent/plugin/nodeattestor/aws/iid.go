package aws

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	pluginName                  = "aws_iid"
	defaultIdentityDocumentUrl  = "http://169.254.169.254/latest/dynamic/instance-identity/document"
	defaultIdentitySignatureUrl = "http://169.254.169.254/latest/dynamic/instance-identity/signature"
)

type IIDAttestorConfig struct {
	TrustDomain          string `hcl:"trust_domain"`
	IdentityDocumentUrl  string `hcl:"identity_document_url"`
	IdentitySignatureUrl string `hcl:"identity_signature_url"`
}

type IIDAttestorPlugin struct {
	trustDomain          string
	identityDocumentUrl  string
	identitySignatureUrl string

	mtx *sync.RWMutex
}

func (p *IIDAttestorPlugin) spiffeID(awsAccountId, awsInstanceId string) *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, awsAccountId, awsInstanceId)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}
	return id
}

func httpGetBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
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

func (p *IIDAttestorPlugin) FetchAttestationData(req *nodeattestor.FetchAttestationDataRequest) (*nodeattestor.FetchAttestationDataResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	docBytes, err := httpGetBytes(p.identityDocumentUrl)
	if err != nil {
		err = aws.AttestationStepError("retrieving the IID from AWS", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	var doc aws.InstanceIdentityDocument
	err = json.Unmarshal(docBytes, &doc)
	if err != nil {
		err = aws.AttestationStepError("unmarshaling the IID", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	sigBytes, err := httpGetBytes(p.identitySignatureUrl)
	if err != nil {
		err = aws.AttestationStepError("retrieving the IID signature from AWS", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	attestedData := aws.IidAttestedData{
		Document:  string(docBytes),
		Signature: string(sigBytes),
	}

	respData, err := json.Marshal(attestedData)
	if err != nil {
		err = aws.AttestationStepError("marshaling the attested data", err)
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	// FIXME: NA should be the one dictating type of this message
	// Change the proto to just take plain byte here
	data := &common.AttestedData{
		Type: pluginName,
		Data: respData,
	}

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: data,
		SpiffeId:     p.spiffeID(doc.AccountId, doc.InstanceId).String(),
	}

	return resp, nil
}

func (p *IIDAttestorPlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

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

	// Set local vars from config struct
	p.trustDomain = config.TrustDomain

	if config.IdentityDocumentUrl != "" {
		p.identityDocumentUrl = config.IdentityDocumentUrl
	} else {
		p.identityDocumentUrl = defaultIdentityDocumentUrl
	}

	if config.IdentitySignatureUrl != "" {
		p.identitySignatureUrl = config.IdentitySignatureUrl
	} else {
		p.identitySignatureUrl = defaultIdentitySignatureUrl
	}

	return resp, nil
}

func (*IIDAttestorPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewIID() nodeattestor.NodeAttestor {
	return &IIDAttestorPlugin{
		mtx: &sync.RWMutex{},
	}
}
