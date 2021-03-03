package gcp

import (
	"bytes"
	"text/template"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	PluginName = "gcp_iit"
)

// DefaultAgentPathTemplate is the default text/template
var DefaultAgentPathTemplate = template.Must(template.New("agent-path").Parse("{{ .PluginName }}/{{ .ProjectID }}/{{ .InstanceID }}"))

type IdentityToken struct {
	jwt.StandardClaims

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
func MakeSpiffeID(trustDomain spiffeid.TrustDomain, agentPathTemplate *template.Template, computeEngine ComputeEngine) (spiffeid.ID, error) {
	var agentPath bytes.Buffer
	if err := agentPathTemplate.Execute(&agentPath, agentPathTemplateData{
		ComputeEngine: computeEngine,
		PluginName:    PluginName,
	}); err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(trustDomain, agentPath.String()), nil
}
