package aws

import (
	"bytes"
	"text/template"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
)

var defaultAgentPathTemplate = template.Must(template.New("agent-svid").Parse("{{ .PluginName}}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}"))

type agentPathTemplateData struct {
	InstanceID  string
	AccountID   string
	Region      string
	PluginName  string
	TrustDomain spiffeid.TrustDomain
	Tags        instanceTags
}

type instanceTags map[string]string

// makeSpiffeID creates a spiffe ID from IID data
func makeSpiffeID(trustDomain spiffeid.TrustDomain, agentPathTemplate *template.Template, doc ec2metadata.EC2InstanceIdentityDocument, tags instanceTags) (spiffeid.ID, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		InstanceID: doc.InstanceID,
		AccountID:  doc.AccountID,
		Region:     doc.Region,
		PluginName: aws.PluginName,
		Tags:       tags,
	}); err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(trustDomain, agentPath.String()), nil
}
