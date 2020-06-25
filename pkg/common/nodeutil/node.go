package nodeutil

import (
	"github.com/spiffe/spire/proto/spire/common"
)

// IsAgentBanned determines if a given attested node is banned or not.
// An agent is considered as "banned" if its serial numbers (current and new)
// are set to empty.
func IsAgentBanned(node common.AttestedNode) bool {
	if node.CertSerialNumber == "" && node.NewCertSerialNumber == "" {
		return true
	}
	return false
}
