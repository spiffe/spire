package nodeutil

import (
	"errors"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsAgentBanned determines if a given attested node is banned or not.
// An agent is considered as "banned" if its X509 SVID serial number is empty.
func IsAgentBanned(node *common.AttestedNode) bool {
	return node.CertSerialNumber == ""
}

// ShouldAgentReattest returns true if the Server returned an error worth rebooting the Agent
func ShouldAgentReattest(err error) bool {
	errStatus := status.Convert(errors.Unwrap(err))
	if errStatus.Code() != codes.PermissionDenied {
		return false
	}

	for _, errDetail := range errStatus.Details() {
		if details, ok := errDetail.(*types.PermissionDeniedDetails); ok {
			switch details.Reason {
			case types.PermissionDeniedDetails_AGENT_EXPIRED,
				types.PermissionDeniedDetails_AGENT_NOT_ACTIVE,
				types.PermissionDeniedDetails_AGENT_NOT_ATTESTED:
				return true
			}
		}
	}
	return false
}
