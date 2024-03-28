package gcp

import (
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	PluginName = "gcp_iit"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .ProjectID }}/{{ .InstanceID }}")

type IdentityToken struct {
	jwt.Claims

	AuthorizedParty string `json:"azp"`
	Google          Google `json:"google"`
}

type Google struct {
	ComputeEngine ComputeEngine `json:"compute_engine"`
}

type ComputeEngine struct {
	ProjectID                 string `json:"project_id"`
	ProjectNumber             int64  `json:"project_number"`
	Zone                      string `json:"zone"`
	InstanceID                string `json:"instance_id"`
	InstanceName              string `json:"instance_name"`
	InstanceCreationTimestamp int64  `json:"instance_creation_timestamp"`
}

type agentPathTemplateData struct {
	ComputeEngine
	PluginName string
}

// MakeAgentID makes an agent SPIFFE ID. The ID always has a host value equal to the given trust domain,
// the path is created using the given agentPathTemplate which is given access to a fully populated
// ComputeEngine object.
func MakeAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, computeEngine ComputeEngine) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		ComputeEngine: computeEngine,
		PluginName:    PluginName,
	})
	if err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(td, agentPath)
}
