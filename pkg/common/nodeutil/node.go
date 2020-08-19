package nodeutil

import (
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsAgentBanned determines if a given attested node is banned or not.
// An agent is considered as "banned" if its X509 SVID serial number is empty.
func IsAgentBanned(node *common.AttestedNode) bool {
	return node.CertSerialNumber == ""
}

// IsShutdownError returns true if the Server returned an error worth rebooting the Agent
func IsShutdownError(err error) bool {
	errStatus := status.Convert(err)
	if errStatus.Code() != codes.PermissionDenied {
		return false
	}

	for _, errDetail := range errStatus.Details() {
		errReason, _ := errDetail.(*types.PermissionDeniedDetails)
		if errReason.Reason == types.PermissionDeniedDetails_AGENT_EXPIRED ||
			errReason.Reason == types.PermissionDeniedDetails_AGENT_NOT_ACTIVE ||
			errReason.Reason == types.PermissionDeniedDetails_AGENT_NOT_ATTESTED {
			return true
		}
	}
	return false
}
