package errorutil

import (
	"fmt"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WrapError creates a new error in the format: "<newErrStr>: <err>".
// This function is intended to be used to wrap errors
// when an error is received from calling a function/method inside of a function or private method.
func WrapError(err error, newErrStr string) error {
	return fmt.Errorf(newErrStr+": %v", err)
}

// PermissionDenied formats a PermissionDenied error with an error string.
func PermissionDenied(reason types.PermissionDeniedDetails_Reason, format string, args ...any) error {
	st := status.Newf(codes.PermissionDenied, format, args...)
	if detailed, err := st.WithDetails(&types.PermissionDeniedDetails{Reason: reason}); err == nil {
		st = detailed
	}

	return st.Err()
}
