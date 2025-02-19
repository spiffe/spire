package audit_test

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAudit(t *testing.T) {
	log, logHook := test.NewNullLogger()

	for _, tt := range []struct {
		name      string
		addFields logrus.Fields
		expect    []spiretest.LogEntry
	}{
		{
			name: "no fields added",
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						"a":              "1",
						"b":              "2",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()

			auditLog.AddFields(tt.addFields)
			auditLog.Audit()
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}

func TestAuditWithFields(t *testing.T) {
	log, logHook := test.NewNullLogger()

	for _, tt := range []struct {
		name            string
		addFields       logrus.Fields
		expect          []spiretest.LogEntry
		parameterFields logrus.Fields
	}{
		{
			name: "no fields added",
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						"a":              "1",
						"b":              "2",
					},
				},
			},
		},
		{
			name: "with parameter fields",
			parameterFields: logrus.Fields{
				"emit": "test",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						"emit":           "test",
					},
				},
			},
		},
		{
			name: "with parameter fields and added",
			addFields: logrus.Fields{
				"a": "1",
				"b": "2",
			},
			parameterFields: logrus.Fields{
				"emit": "test",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						"emit":           "test",
						"a":              "1",
						"b":              "2",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()

			auditLog.AddFields(tt.addFields)
			auditLog.AuditWithFields(tt.parameterFields)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}

func TestAuditWitTypesStatus(t *testing.T) {
	log, logHook := test.NewNullLogger()

	for _, tt := range []struct {
		name            string
		status          *types.Status
		expect          []spiretest.LogEntry
		parameterFields logrus.Fields
	}{
		{
			name:   "no error no fields",
			status: &types.Status{Code: int32(codes.OK), Message: "ok"},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:   "no error with fields",
			status: &types.Status{Code: int32(codes.OK), Message: "ok"},
			parameterFields: logrus.Fields{
				"emit": "test",
			},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						"emit":           "test",
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "some error",
						telemetry.Type:          "audit",
					},
				},
			},
		},
		{
			name:            "error with fields",
			status:          &types.Status{Code: int32(codes.Internal), Message: "some error"},
			parameterFields: logrus.Fields{"emit": "test"},
			expect: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						"emit":                  "test",
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "some error",
						telemetry.Type:          "audit",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()
			auditLog.AuditWithTypesStatus(tt.parameterFields, tt.status)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}

func TestAuditWithError(t *testing.T) {
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Type:          "audit",
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid argument",
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Type:          "audit",
						telemetry.Status:        "error",
						telemetry.StatusCode:    "Unknown",
						telemetry.StatusMessage: "some error",
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Type:          "audit",
						telemetry.Status:        "error",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid argument",
						"a":                     "1",
						"b":                     "2",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := audit.New(log)
			logHook.Reset()

			auditLog.AddFields(tt.addFields)
			auditLog.AuditWithError(tt.err)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expect)
		})
	}
}
