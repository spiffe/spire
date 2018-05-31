package gcp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

	cgcp "github.com/spiffe/spire/pkg/common/plugin/gcp"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	pluginName           = "gcp_iid"
	defaultGoogleCertURL = "https://www.googleapis.com/oauth2/v1/certs"

	defaultMaxTokenLifetimeSecs int64 = 86400 // 1 day in seconds
	defaultClockSkewSecs        int64 = 300   // 5 min in seconds
)

type IIDAttestorConfig struct {
	TrustDomain          string `hcl:"trust_domain"`
	Audience             string `hcl:"audience"`
	GoogleCertURL        string `hcl:"google_cert_url"`
	MaxTokenLifetimeSecs int64  `hcl:"max_token_lifetime_secs"`
	ClockSkewSecs        int64  `hcl:"clock_skew_secs"`
}

type IIDAttestorPlugin struct {
	trustDomain          string
	audience             string
	googleCertURL        string
	maxTokenLifetimeSecs int64
	clockSkewSecs        int64
	mtx                  *sync.Mutex
}

func (p *IIDAttestorPlugin) spiffeID(gcpAccountID string, gcpInstanceID string) *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, gcpAccountID, gcpInstanceID)
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

func (p *IIDAttestorPlugin) Attest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {

	var attestedData cgcp.IIDAttestedData
	err := json.Unmarshal(req.AttestedData.Data, &attestedData)
	if err != nil {
		err = cgcp.AttestationStepError("unmarshalling the attestation data", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	var token cgcp.IdentityToken
	err = json.Unmarshal([]byte(attestedData.Token), &token)
	if err != nil {
		err = cgcp.AttestationStepError("unmarshalling the IdentityToken", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	if req.AttestedBefore {
		err = cgcp.AttestationStepError("validation the InstanceID", fmt.Errorf("the InstanceID has been used and cannot be registered again"))
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	var header cgcp.Header
	err = json.Unmarshal([]byte(attestedData.Token), &header)
	if err != nil {
		err = cgcp.AttestationStepError("unmarshalling the IdentityToken header", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	playloadToSign := base64.RawURLEncoding.EncodeToString([]byte(attestedData.Header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(attestedData.Token))
	fmt.Println(playloadToSign)

	p.mtx.Lock()
	defer p.mtx.Unlock()

	signatureTokensBytes, err := httpGetBytes(p.googleCertURL)
	if err != nil {
		err = cgcp.AttestationStepError("retrieving public certificates tokes", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	var signatureTokens map[string]string
	err = json.Unmarshal(signatureTokensBytes, &signatureTokens)
	if err != nil {
		err = cgcp.AttestationStepError("unmarshalling public certificates tokes", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	err = verifySignature([]byte(playloadToSign), attestedData.Signature, signatureTokens)
	if err != nil {
		err = cgcp.AttestationStepError("validating IdentityToken signature", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	err = verifyTimeRange(token, p.maxTokenLifetimeSecs, p.clockSkewSecs)
	if err != nil {
		err = cgcp.AttestationStepError("checking IdentityToken validity timeframe", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	err = verifyAudience(p.audience, token)
	if err != nil {
		err = cgcp.AttestationStepError("checking IdentityToken audience", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: p.spiffeID(token.Google.ComputeEngine.ProjectID, token.Google.ComputeEngine.InstanceID).String(),
	}
	return resp, nil
}

func verifySignature(payload []byte, signature []byte, certs map[string]string) error {
	hashed := sha256.Sum256(payload)
	for _, certString := range certs {
		block, _ := pem.Decode([]byte(certString))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
		if err == nil {
			return nil
		}
		if err != nil && err != rsa.ErrVerification {
			return err
		}

	}
	return fmt.Errorf("Signature not valid")
}

func verifyTimeRange(token cgcp.IdentityToken, maxTokenLifetimeSecs int64, clockSkewSecs int64) error {
	now := time.Now().Unix()

	if token.ExpiresAt >= now+maxTokenLifetimeSecs {
		return fmt.Errorf("exp field is too far in the future")
	}

	earliest := token.IssuedAt - clockSkewSecs
	if now < earliest {
		return fmt.Errorf("Token used too early, %v < %v", now, earliest)
	}
	latest := token.ExpiresAt + clockSkewSecs
	if now > latest {
		return fmt.Errorf("Token used too late, %v > %v", now, latest)
	}
	return nil
}

func verifyAudience(audience string, token cgcp.IdentityToken) error {
	if token.Audience == "" {
		return fmt.Errorf("Audience in token is empty")
	}

	if token.Audience != audience {
		return fmt.Errorf("Audience in token doesn't match configured Audience, %v != %v", token.Audience, audience)
	}

	return nil
}

func (p *IIDAttestorPlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	config := &IIDAttestorConfig{}
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

	if config.Audience == "" {
		err := fmt.Errorf("Missing audience configuration parameter")
		return resp, err
	}
	p.audience = config.Audience

	if config.TrustDomain == "" {
		err := fmt.Errorf("Missing trust_domain configuration parameter")
		return resp, err
	}
	p.trustDomain = config.TrustDomain

	if config.GoogleCertURL != "" {
		p.googleCertURL = config.GoogleCertURL
	} else {
		p.googleCertURL = defaultGoogleCertURL
	}

	if config.ClockSkewSecs != 0 {
		p.clockSkewSecs = config.ClockSkewSecs
	} else {
		p.clockSkewSecs = defaultClockSkewSecs
	}

	if config.MaxTokenLifetimeSecs != 0 {
		p.maxTokenLifetimeSecs = config.MaxTokenLifetimeSecs
	} else {
		p.maxTokenLifetimeSecs = defaultMaxTokenLifetimeSecs
	}

	return resp, nil
}

func (*IIDAttestorPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewIID() nodeattestor.NodeAttestor {
	return &IIDAttestorPlugin{
		mtx: &sync.Mutex{},
	}
}
