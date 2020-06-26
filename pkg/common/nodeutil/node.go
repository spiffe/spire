package nodeutil

import (
	"github.com/spiffe/spire/proto/spire/common"
)

// IsAgentBanned determines if a given attested node is banned or not.
// An agent is considered as "banned" if its X509 SVID serial number is empty.
func IsAgentBanned(node *common.AttestedNode) bool {
	if node.CertSerialNumber == "" {
		return true
	}
	return false
}
