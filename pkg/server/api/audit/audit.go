package audit

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
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
	fields logrus.Fields
	log    logrus.FieldLogger
}

func New(l logrus.FieldLogger) Logger {
	return &logger{
		log: l.WithFields(logrus.Fields{
			telemetry.Type: "audit",
			// It is success by default, errors must change it
			telemetry.Status: "success",
		}),
		fields: logrus.Fields{},
	}
}

func (l *logger) AddFields(fields logrus.Fields) {
	for key, value := range fields {
		l.fields[key] = value
	}
}

func (l *logger) Audit() {
	l.log.WithFields(l.fields).Info(message)
}

func (l *logger) AuditWithFields(fields logrus.Fields) {
	l.log.WithFields(l.fields).WithFields(fields).Info(message)
}

func (l *logger) AuditWithError(err error) {
	fields := fieldsFromError(err)
	l.log.WithFields(l.fields).WithFields(fields).Info(message)
}

func (l *logger) AuditWithTypesStatus(fields logrus.Fields, s *types.Status) {
	statusFields := fieldsFromStatus(s)
	l.log.WithFields(statusFields).WithFields(fields).Info(message)
}

func fieldsFromStatus(s *types.Status) logrus.Fields {
	err := status.Error(codes.Code(s.Code), s.Message)
	return fieldsFromError(err)
}

func fieldsFromError(err error) logrus.Fields {
	fields := logrus.Fields{}
	// Unknown status is returned for non proto status
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
