package errorutil

import (
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PermissionDenied formats a PermissionDenied error with an error string.
func PermissionDenied(reason types.PermissionDeniedDetails_Reason, format string, args ...any) error {
	st := status.Newf(codes.PermissionDenied, format, args...)
	if detailed, err := st.WithDetails(&types.PermissionDeniedDetails{Reason: reason}); err == nil {
		st = detailed
	}

	return st.Err()
}
