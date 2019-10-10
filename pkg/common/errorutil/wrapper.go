package errorutil

import (
	"fmt"
)

// WrapAndLogError creates a new error in the format: "<newErrStr>: <err>".
// This function is intended to be used to wrap errors
// when an error is received from calling a function/method inside of a function or private method.
func WrapError(err error, newErrStr string) error {
	return fmt.Errorf(newErrStr + ": %v", err)
}
