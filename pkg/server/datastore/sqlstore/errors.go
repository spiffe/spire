package sqlstore

import (
	"fmt"
)

const (
	datastoreSQLErrorPrefix        = "datastore-sql"
	datastoreValidationErrorPrefix = "datastore-validation"
)

type sqlError struct {
	err error
	msg string
}

func newSQLError(fmtMsg string, args ...any) error {
	return &sqlError{
		msg: fmt.Sprintf(fmtMsg, args...),
	}
}

func newWrappedSQLError(err error) error {
	if err == nil {
		return nil
	}

	return &sqlError{
		err: err,
	}
}

func (s *sqlError) Error() string {
	if s == nil {
		return ""
	}

	if s.err != nil {
		return fmt.Sprintf("%s: %s", datastoreSQLErrorPrefix, s.err)
	}

	return fmt.Sprintf("%s: %s", datastoreSQLErrorPrefix, s.msg)
}

func (s *sqlError) Is(err error) bool {
	if s == nil {
		return false
	}

	sErr, ok := err.(*sqlError)
	if !ok {
		return false
	}

	return s.msg == sErr.msg
}

func (s *sqlError) Unwrap() error {
	if s == nil {
		return nil
	}

	return s.err
}

type validationError struct {
	err error
	msg string
}

func newValidationError(fmtMsg string, args ...any) error {
	return &validationError{
		msg: fmt.Sprintf(fmtMsg, args...),
	}
}

func newWrappedValidationError(err error) error {
	if err == nil {
		return nil
	}

	return &validationError{
		err: err,
	}
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

func (v *validationError) Is(err error) bool {
	if v == nil {
		return false
	}

	vErr, ok := err.(*validationError)
	if !ok {
		return false
	}

	return v.msg == vErr.msg
}

func (v *validationError) Unwrap() error {
	if v == nil {
		return nil
	}

	return v.err
}
