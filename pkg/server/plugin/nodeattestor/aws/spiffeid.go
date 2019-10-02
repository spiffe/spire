package aws

import (
	"bytes"
	"net/url"
	"text/template"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
)

var defaultAgentPathTemplate = template.Must(template.New("agent-svid").Parse("{{ .PluginName}}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}"))

type agentPathTemplateData struct {
	aws.InstanceIdentityDocument
	PluginName  string
	TrustDomain string
}

// makeSpiffeID creates a spiffe ID from IID data
func makeSpiffeID(trustDomain string, agentPathTemplate *template.Template, doc aws.InstanceIdentityDocument) (*url.URL, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		InstanceIdentityDocument: doc,
		PluginName:               aws.PluginName,
	}); err != nil {
		return nil, err
	}

	return idutil.AgentURI(trustDomain, agentPath.String()), nil
}
