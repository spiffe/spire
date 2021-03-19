package api

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateStatus creates a proto Status
func CreateStatus(code codes.Code, format string, a ...interface{}) *types.Status {
	return &types.Status{
		Code:    int32(code),
		Message: fmt.Sprintf(format, a...),
	}
}

// OK creates a success proto status
func OK() *types.Status {
	return CreateStatus(codes.OK, codes.OK.String())
}

// MakeStatus logs and returns a status composed of: msg, err and code.
// Errors are treated differently according to its gRPC code.
func MakeStatus(log logrus.FieldLogger, code codes.Code, msg string, err error) *types.Status {
	e := MakeErr(log, code, msg, err)
	if e == nil {
		return OK()
	}

	return CreateStatus(code, status.Convert(e).Message())
}

// MakeErr logs and returns an error composed of: msg, err and code.
// Errors are treated differently according to its gRPC code.
func MakeErr(log logrus.FieldLogger, code codes.Code, msg string, err error) error {
	errMsg := msg
	switch code {
	case codes.OK:
		// It is not expected for MakeErr to be called with nil
		// but we make a case for it in the switch to prevent it to
		// go to the default case
		return nil

	case codes.InvalidArgument:
		// Add the prefix 'Invalid argument' for InvalidArgument errors
		if err != nil {
			log = log.WithError(err)
			errMsg = concatErr(msg, err)
		}

		log.Errorf("Invalid argument: %s", msg)
		return status.Error(code, errMsg)

	case codes.NotFound:
		// Do not log nor return the inner error for NotFound errors
		log.Error(capitalize(msg))
		return status.Error(code, errMsg)

	default:
		if err != nil {
			log = log.WithError(err)
			errMsg = concatErr(msg, err)
		}
		log.Error(capitalize(msg))
		return status.Error(code, errMsg)
	}
}

// Concat message with provided error and avoid "status.Code"
func concatErr(msg string, err error) string {
	protoStatus := status.Convert(err)
	// Proto will be nil "only" when err is nil
	if protoStatus == nil {
		return msg
	}

	return fmt.Sprintf("%s: %s", msg, protoStatus.Message())
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}
