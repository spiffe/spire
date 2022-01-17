package gcp

import (
	"net/url"

	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	PluginName = "gcp_iit"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = agentpathtemplate.MustParse("{{ .PluginName }}/{{ .ProjectID }}/{{ .InstanceID }}")

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

// MakeSpiffeID makes an agent spiffe ID. The ID always has a host value equal to the given trust domain,
// the path is created using the given agentPathTemplate which is given access to a fully populated
// ComputeEngine object.
func MakeSpiffeID(trustDomain string, agentPathTemplate *agentpathtemplate.Template, computeEngine ComputeEngine) (*url.URL, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		ComputeEngine: computeEngine,
		PluginName:    PluginName,
	})
	if err != nil {
		return nil, err
	}

	return idutil.AgentURI(trustDomain, agentPath), nil
}
