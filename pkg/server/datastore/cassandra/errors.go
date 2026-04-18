package cassandra

import (
	"fmt"
)

const (
	datastoreValidationErrorPrefix = "datastore-validation"
)

var NotFoundErr = newCassandraError("record not found")

type cassandraError struct {
	err error
	msg string
}

func (s *cassandraError) Error() string {
	if s == nil {
		return ""
	}

	if s.err != nil {
		return s.err.Error()
	}

	return s.msg
}

func (s *cassandraError) Unwrap() error {
	if s == nil {
		return nil
	}

	return s.err
}

type validationError struct {
	err error
	msg string
}

func (v *validationError) Error() string {
	if v == nil {
		return ""
	}

	if v.err != nil {
		return fmt.Sprintf("%s: %s", datastoreValidationErrorPrefix, v.err)
	}

	return fmt.Sprintf("%s: %s", datastoreValidationErrorPrefix, v.msg)
}

func (v *validationError) Unwrap() error {
	if v == nil {
		return nil
	}

	return v.err
}

func newCassandraError(fmtMsg string, args ...any) error {
	return &cassandraError{
		msg: fmt.Sprintf(fmtMsg, args...),
	}
}

func newWrappedCassandraError(err error) error {
	if err == nil {
		return nil
	}

	return &cassandraError{
		err: err,
	}
}

func newValidationError(fmtMsg string, args ...any) error {
	return &validationError{
		msg: fmt.Sprintf(fmtMsg, args...),
	}
}
