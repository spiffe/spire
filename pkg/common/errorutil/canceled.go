package errorutil

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsCanceled returns true if err indicates that an operation was canceled.
func IsCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled
}
