package audit

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Log interface {
	AddFields(logrus.Fields)
	Emit(logrus.Fields)
	EmitBatch(*types.Status, logrus.Fields)
	EmitError(error)
}

type log struct {
	fields logrus.Fields
	log    logrus.FieldLogger
}

func New(l logrus.FieldLogger) Log {
	return &log{
		log: l.WithFields(logrus.Fields{
			"type": "audit",
			// It is success by default, erros must change it
			"status": "success",
		}),
		fields: logrus.Fields{},
	}
}

func (l *log) AddFields(fields logrus.Fields) {
	for key, value := range fields {
		l.fields[key] = value
	}
}

func (l *log) Emit(fields logrus.Fields) {
	l.log.WithFields(l.fields).WithFields(fields).Info("Audit log")
}

func (l *log) EmitError(err error) {
	fields := fieldsFromError(err)
	l.log.WithFields(l.fields).WithFields(fields).Info("Audit log")
}

func (l *log) EmitBatch(s *types.Status, fields logrus.Fields) {
	statusFields := fieldsFromStatus(s)
	l.log.WithFields(statusFields).WithFields(fields).Info("Audit log")
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
		fields["status"] = "success"
	default:
		fields["status"] = "error"
		fields["status_code"] = statusErr.Code()
		fields["status_message"] = statusErr.Message()
	}

	return fields
}
