package azure

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	ImdsPluginName = "azure_imds"
)

var DefaultIMDSAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .TenantID }}/{{ .SubscriptionID }}/{{ .VMID }}")

// AgentUntrustedMetadata is the untrusted metadata for the IMDS attestation payload.
// Used to help point the server to the correct tenant and VMSS
type AgentUntrustedMetadata struct {
	AgentDomain string  `json:"agentDomain"`
	VMSSName    *string `json:"vmssName"`
}

type IMDSAttestationPayload struct {
	Document AttestedDocument `json:"document"`
	// Nothing in the metadata should ever be trusted, it is used to help point the server to the correct tenant and VMSS
	Metadata AgentUntrustedMetadata `json:"metadata"`
}

type AttestedDocument struct {
	Encoding  string `json:"encoding"`
	Signature string `json:"signature"`
}

type AttestedDocumentContent struct {
	SubscriptionID string `json:"subscriptionId"`
	VMID           string `json:"vmId"`
	Nonce          string `json:"nonce"`
	// TenantID does not actually come from the document, it is added by the server for convenience
	TenantID string `json:"tid"`
}

func FetchAttestedDocument(cl HTTPClient, nonce string) (*AttestedDocument, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/attested/document", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata", "true")

	params := req.URL.Query()
	params.Set("nonce", nonce)
	params.Set("api-version", "2025-04-07")
	req.URL.RawQuery = params.Encode()

	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, tryRead(resp.Body))
	}

	metadata := new(AttestedDocument)
	if err := json.NewDecoder(resp.Body).Decode(metadata); err != nil {
		return nil, fmt.Errorf("unable to decode response: %w", err)
	}

	switch {
	case metadata.Encoding == "":
		return nil, errors.New("response missing encoding")
	case metadata.Signature == "":
		return nil, errors.New("response missing signature")

	}

	return metadata, nil
}

type imdsAgentPathTemplateData struct {
	*AttestedDocumentContent
	PluginName string
}

func MakeIMDSAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, data *AttestedDocumentContent) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(imdsAgentPathTemplateData{
		AttestedDocumentContent: data,
		PluginName:              ImdsPluginName,
	})
	if err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(td, agentPath)
}
