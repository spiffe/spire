package audit

import (
	"maps"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	message = "API accessed"
)

type Logger interface {
	AddFields(logrus.Fields)
	Audit()
	AuditWithFields(logrus.Fields)
	AuditWithTypesStatus(logrus.Fields, *types.Status)
	AuditWithError(error)
}

type logger struct {
	fields     logrus.Fields
	log        logrus.FieldLogger
	onlyErrors bool
}

func New(l logrus.FieldLogger) Logger {
	return newLogger(l, false)
}

// NewErrorOnly creates an audit logger that omits successful operations.
func NewErrorOnly(l logrus.FieldLogger) Logger {
	return newLogger(l, true)
}

func newLogger(l logrus.FieldLogger, onlyErrors bool) Logger {
	return &logger{
		log: l.WithFields(logrus.Fields{
			telemetry.Type: "audit",
			// It is success by default, errors must change it
			telemetry.Status: "success",
		}),
		fields:     logrus.Fields{},
		onlyErrors: onlyErrors,
	}
}

func (l *logger) AddFields(fields logrus.Fields) {
	maps.Copy(l.fields, fields)
}

func (l *logger) Audit() {
	if l.onlyErrors {
		return
	}
	l.log.WithFields(l.fields).Info(message)
}

func (l *logger) AuditWithFields(fields logrus.Fields) {
	if l.onlyErrors {
		return
	}
	l.log.WithFields(l.fields).WithFields(fields).Info(message)
}

func (l *logger) AuditWithError(err error) {
	if l.onlyErrors && status.Code(err) == codes.OK {
		return
	}
	fields := fieldsFromError(err)
	l.log.WithFields(l.fields).WithFields(fields).Info(message)
}

func (l *logger) AuditWithTypesStatus(fields logrus.Fields, s *types.Status) {
	if l.onlyErrors && s.Code == int32(codes.OK) {
		return
	}
	statusFields := fieldsFromStatus(s)
	l.log.WithFields(statusFields).WithFields(fields).Info(message)
}

func fieldsFromStatus(s *types.Status) logrus.Fields {
	err := status.Error(util.MustCast[codes.Code](s.Code), s.Message)
	return fieldsFromError(err)
}

func fieldsFromError(err error) logrus.Fields {
	fields := logrus.Fields{}
	// Unknown status is returned for non-proto status
	statusErr, _ := status.FromError(err)
	switch {
	case statusErr.Code() == codes.OK:
		fields[telemetry.Status] = "success"
	default:
		fields[telemetry.Status] = "error"
		fields[telemetry.StatusCode] = statusErr.Code()
		fields[telemetry.StatusMessage] = statusErr.Message()
	}

	return fields
}
