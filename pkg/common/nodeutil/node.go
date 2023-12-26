package nodeutil

import (
	"errors"
	"strings"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	shouldReattest = map[types.PermissionDeniedDetails_Reason]struct{}{
		types.PermissionDeniedDetails_AGENT_EXPIRED:       {},
		types.PermissionDeniedDetails_AGENT_NOT_ACTIVE:    {},
		types.PermissionDeniedDetails_AGENT_NOT_ATTESTED:  {},
		types.PermissionDeniedDetails_AGENT_MUST_REATTEST: {},
	}
	shouldShutDown = map[types.PermissionDeniedDetails_Reason]struct{}{
		types.PermissionDeniedDetails_AGENT_BANNED: {},
	}
	unknowAuthorityErr = "x509: certificate signed by unknown authority"
)

// IsAgentBanned determines if a given attested node is banned or not.
// An agent is considered as "banned" if its X509 SVID serial number is empty.
func IsAgentBanned(node *common.AttestedNode) bool {
	return node.CertSerialNumber == ""
}

// ShouldAgentReattest returns true if the Server returned an error worth rebooting the Agent
func ShouldAgentReattest(err error) bool {
	return isExpectedPermissionDenied(err, shouldReattest)
}

// IsUnknownAuthorityError returns tru if the Server returned an unknow authority error when verifying
// presented SVID
func IsUnknownAuthorityError(err error) bool {
	if err == nil {
		return false
	}

	// Since it is an rpc error we are unable to use errors.As since it is not possible to unwrap
	return strings.Contains(err.Error(), unknowAuthorityErr)
}

// ShouldAgentShutdown returns true if the Server returned an error worth shutting down the Agent
func ShouldAgentShutdown(err error) bool {
	return isExpectedPermissionDenied(err, shouldShutDown)
}

func isExpectedPermissionDenied(err error, expectedReason map[types.PermissionDeniedDetails_Reason]struct{}) bool {
	errStatus := status.Convert(errors.Unwrap(err))
	if errStatus.Code() != codes.PermissionDenied {
		return false
	}

	for _, errDetail := range errStatus.Details() {
		if details, ok := errDetail.(*types.PermissionDeniedDetails); ok {
			if _, ok := expectedReason[details.Reason]; ok {
				return true
			}
		}
	}
	return false
}
