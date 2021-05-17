package audit_test

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEmit(t *testing.T) {
	log, logHook := test.NewNullLogger()

	for _, tt := range []struct {
		name       string
		addFields  logrus.Fields
		expect     []spiretest.LogEntry
		emitFields logrus.Fields
	}{
		{
			name: "no fields added",
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
					},
				},
			},
		},
		{
			name: "with fields added",
			addFields: logrus.Fields{
				"a": "1",
				"b": "2",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
						"a":      "1",
						"b":      "2",
					},
				},
			},
		},
		{
			name: "with fields on emit",
			emitFields: logrus.Fields{
				"emit": "test",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
						"emit":   "test",
					},
				},
			},
		},
		{
			name: "with fields on emit and added",
			addFields: logrus.Fields{
				"a": "1",
				"b": "2",
			},
			emitFields: logrus.Fields{
				"emit": "test",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
						"emit":   "test",
						"a":      "1",
						"b":      "2",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()

			auditLog.AddFields(tt.addFields)
			auditLog.Emit(tt.emitFields)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}

func TestEmitBatch(t *testing.T) {
	log, logHook := test.NewNullLogger()

	for _, tt := range []struct {
		name       string
		status     *types.Status
		expect     []spiretest.LogEntry
		emitFields logrus.Fields
	}{
		{
			name:   "no error no fields",
			status: &types.Status{Code: int32(codes.OK), Message: "ok"},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
					},
				},
			},
		},
		{
			name:   "no error with fields",
			status: &types.Status{Code: int32(codes.OK), Message: "ok"},
			emitFields: logrus.Fields{
				"emit": "test",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
						"emit":   "test",
					},
				},
			},
		},
		{
			name:   "error and no fields",
			status: &types.Status{Code: int32(codes.Internal), Message: "some error"},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status":         "error",
						"status_code":    "Internal",
						"status_message": "some error",
						"type":           "audit",
					},
				},
			},
		},
		{
			name:       "error with fields",
			status:     &types.Status{Code: int32(codes.Internal), Message: "some error"},
			emitFields: logrus.Fields{"emit": "test"},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"emit":           "test",
						"status":         "error",
						"status_code":    "Internal",
						"status_message": "some error",
						"type":           "audit",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()
			auditLog.EmitBatch(tt.status, tt.emitFields)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}

func TestEmitError(t *testing.T) {
	log, logHook := test.NewNullLogger()

	for _, tt := range []struct {
		name      string
		addFields logrus.Fields
		expect    []spiretest.LogEntry
		err       error
	}{
		{
			name: "no fields, no error",
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"status": "success",
						"type":   "audit",
					},
				},
			},
		},
		{
			name: "no fields, status error",
			err:  status.Error(codes.InvalidArgument, "invalid argument"),
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"type":           "audit",
						"status":         "error",
						"status_code":    "InvalidArgument",
						"status_message": "invalid argument",
					},
				},
			},
		},
		{
			name: "no fields, regular error",
			err:  errors.New("some error"),
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"type":           "audit",
						"status":         "error",
						"status_code":    "Unknown",
						"status_message": "some error",
					},
				},
			},
		},
		{
			name: "add fields, status error",
			addFields: logrus.Fields{
				"a": "1",
				"b": "2",
			},
			err: status.Error(codes.InvalidArgument, "invalid argument"),
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Audit log",
					Data: logrus.Fields{
						"type":           "audit",
						"status":         "error",
						"status_code":    "InvalidArgument",
						"status_message": "invalid argument",
						"a":              "1",
						"b":              "2",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()

			auditLog.AddFields(tt.addFields)
			auditLog.EmitError(tt.err)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}
