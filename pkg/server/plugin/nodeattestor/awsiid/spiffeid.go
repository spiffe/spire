package awsiid

import (
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/plugin/aws"
)

var defaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName}}/{{ .AccountID }}/{{ .Region }}/{{ .InstanceID }}")

type agentPathTemplateData struct {
	InstanceID  string
	AccountID   string
	Region      string
	PluginName  string
	TrustDomain string
	Tags        instanceTags
}

type instanceTags map[string]string

// makeAgentID creates an agent ID from IID data
func makeAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, doc imds.InstanceIdentityDocument, tags instanceTags) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		InstanceID: doc.InstanceID,
		AccountID:  doc.AccountID,
		Region:     doc.Region,
		PluginName: aws.PluginName,
		Tags:       tags,
	})
	if err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(td, agentPath)
}
