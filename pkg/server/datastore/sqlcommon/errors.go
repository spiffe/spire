package sqlcommon

import "fmt"

const (
	datastoreSQLErrorPrefix        = "datastore-sql"
	datastoreValidationErrorPrefix = "datastore-validation"
)

type SQLError struct {
	err error
	msg string
}

func (s *SQLError) Error() string {
	if s == nil {
		return ""
	}
	if s.err != nil {
		return fmt.Sprintf("%s: %s", datastoreSQLErrorPrefix, s.err)
	}
	return fmt.Sprintf("%s: %s", datastoreSQLErrorPrefix, s.msg)
}

func (s *SQLError) Unwrap() error {
	if s == nil {
		return nil
	}
	return s.err
}

type ValidationError struct {
	err error
	msg string
}

func (v *ValidationError) Error() string {
	if v == nil {
		return ""
	}
	if v.err != nil {
		return fmt.Sprintf("%s: %s", datastoreValidationErrorPrefix, v.err)
	}
	return fmt.Sprintf("%s: %s", datastoreValidationErrorPrefix, v.msg)
}

func (v *ValidationError) Unwrap() error {
	if v == nil {
		return nil
	}
	return v.err
}

func NewSQLError(fmtMsg string, args ...any) error {
	return &SQLError{msg: fmt.Sprintf(fmtMsg, args...)}
}

func NewWrappedSQLError(err error) error {
	if err == nil {
		return nil
	}
	return &SQLError{err: err}
}

func NewValidationError(fmtMsg string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(fmtMsg, args...)}
}

func NewWrappedValidationError(err error) error {
	if err == nil {
		return nil
	}
	return &ValidationError{err: err}
}
