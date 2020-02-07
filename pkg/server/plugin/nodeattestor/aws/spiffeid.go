package aws

import (
	"bytes"
	"net/url"
	"text/template"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
)

var defaultAgentPathTemplate = template.Must(template.New("agent-svid").Parse("{{ .PluginName}}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}"))

type agentPathTemplateData struct {
	InstanceID  string
	AccountID   string
	Region      string
	PluginName  string
	TrustDomain string
	Tags        instanceTags
}

type instanceTags map[string]string

// makeSpiffeID creates a spiffe ID from IID data
func makeSpiffeID(trustDomain string, agentPathTemplate *template.Template, doc ec2metadata.EC2InstanceIdentityDocument, tags instanceTags) (*url.URL, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		InstanceID: doc.InstanceID,
		AccountID:  doc.AccountID,
		Region:     doc.Region,
		PluginName: aws.PluginName,
		Tags:       tags,
	}); err != nil {
		return nil, err
	}

	return idutil.AgentURI(trustDomain, agentPath.String()), nil
}
