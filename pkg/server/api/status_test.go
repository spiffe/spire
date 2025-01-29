package api_test

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOK(t *testing.T) {
	require.Equal(t, api.OK(), &types.Status{
		Message: "OK",
		Code:    int32(codes.OK),
	})
}

func TestMakeStatus_OK(t *testing.T) {
	l, hook := test.NewNullLogger()
	sts := api.MakeStatus(l, codes.OK, "object successfully created", nil)

	require.Equal(t, &types.Status{
		Message: "OK",
		Code:    int32(codes.OK),
	}, sts)

	require.Empty(t, len(hook.AllEntries()))
}

func TestMakeStatus_Error(t *testing.T) {
	l, hook := test.NewNullLogger()
	sts := api.MakeStatus(l, codes.NotFound, "object not found", nil)

	require.Equal(t, &types.Status{
		Message: "object not found",
		Code:    int32(codes.NotFound),
	}, sts)

	spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.ErrorLevel,
			Message: "Object not found",
		},
	})
}

func TestMakeErr(t *testing.T) {
	for _, tt := range []struct {
		name   string
		code   codes.Code
		msg    string
		err    error
		expErr error
		expLog []spiretest.LogEntry
	}{
		{
			name:   "ok",
			code:   codes.OK,
			msg:    "OK",
			err:    nil,
			expErr: nil,
		},
		{
			name:   "invalid argument with inner error",
			code:   codes.InvalidArgument,
			msg:    "failed to parse object",
			err:    errors.New("the error"),
			expErr: status.Error(codes.InvalidArgument, "failed to parse object: the error"),
			expLog: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse object", // when code is InvalidArgument, a prefix is added
					Data: logrus.Fields{
						logrus.ErrorKey: "the error",
					},
				},
			},
		},
		{
			name:   "invalid argument without inner error",
			code:   codes.InvalidArgument,
			msg:    "failed to parse object",
			err:    nil,
			expErr: status.Error(codes.InvalidArgument, "failed to parse object"),
			expLog: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse object",
				},
			},
		},
		{
			name:   "not found",
			code:   codes.NotFound,
			msg:    "object not found",
			err:    errors.New("the error"), // when code is NotFound, the inner error is ignored
			expErr: status.Error(codes.NotFound, "object not found"),
			expLog: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Object not found",
				},
			},
		},
		{
			name:   "all other error codes with inner error",
			code:   codes.Internal,
			msg:    "failed to build object",
			err:    errors.New("the error"),
			expErr: status.Error(codes.Internal, "failed to build object: the error"),
			expLog: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to build object",
					Data: logrus.Fields{
						logrus.ErrorKey: "the error",
					},
				},
			},
		},
		{
			name:   "all other error codes without inner error",
			code:   codes.Internal,
			msg:    "failed to build object",
			err:    nil,
			expErr: status.Error(codes.Internal, "failed to build object"),
			expLog: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to build object",
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			err := api.MakeErr(log, tt.code, tt.msg, tt.err)
			require.Equal(t, err, tt.expErr)
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expLog)
		})
	}
}
