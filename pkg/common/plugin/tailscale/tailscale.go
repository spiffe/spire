package tailscale

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/idutil"
)

const (
	PluginName = "tailscale"
)

// DefaultAgentPathTemplate is the default text/template for agent SPIFFE IDs.
var DefaultAgentPathTemplate = agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .NodeID }}")

// DeviceInfo holds whois-verified device facts used for SPIFFE ID and selectors.
type DeviceInfo struct {
	NodeID     string
	Hostname   string
	Tags       []string
	OS         string
	Addresses  []string
	User       string
	Authorized bool
}

type agentPathTemplateData struct {
	DeviceInfo
	PluginName string
}

// MakeAgentID creates an agent SPIFFE ID using the given trust domain, template,
// and whois-verified device info.
func MakeAgentID(td spiffeid.TrustDomain, agentPathTemplate *agentpathtemplate.Template, info DeviceInfo) (spiffeid.ID, error) {
	agentPath, err := agentPathTemplate.Execute(agentPathTemplateData{
		DeviceInfo: info,
		PluginName: PluginName,
	})
	if err != nil {
		return spiffeid.ID{}, err
	}

	return idutil.AgentID(td, agentPath)
}
