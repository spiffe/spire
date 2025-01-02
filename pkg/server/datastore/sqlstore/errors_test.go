package sqlstore

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSQLError(t *testing.T) {
	err := newSQLError("an error with two dynamic fields: %s, %d", "hello", 1)
	assert.EqualError(t, err, "datastore-sql: an error with two dynamic fields: hello, 1")

	var sErr *sqlError
	assert.True(t, errors.As(err, &sErr))

	assert.True(t, errors.Is(err, &sqlError{
		msg: "an error with two dynamic fields: hello, 1",
	}))
}

func TestWrappedSQLError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		err := newWrappedSQLError(nil)
		assert.NoError(t, err)
	})

	t.Run("non-nil error", func(t *testing.T) {
		wrappedErr := errors.New("foo")
		err := newWrappedSQLError(wrappedErr)

		assert.EqualError(t, err, "datastore-sql: foo")

		var sErr *sqlError
		assert.True(t, errors.As(err, &sErr))

		assert.True(t, errors.Is(err, &sqlError{
			err: wrappedErr,
		}))
	})
}

func TestValidationError(t *testing.T) {
	err := newValidationError("an error with two dynamic fields: %s, %d", "hello", 1)
	assert.EqualError(t, err, "datastore-validation: an error with two dynamic fields: hello, 1")

	var vErr *validationError
	assert.True(t, errors.As(err, &vErr))

	assert.True(t, errors.Is(err, &validationError{
		msg: "an error with two dynamic fields: hello, 1",
	}))
}

func TestWrappedValidationError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		err := newWrappedValidationError(nil)
		assert.NoError(t, err)
	})

	t.Run("non-nil error", func(t *testing.T) {
		wrappedErr := errors.New("bar")
		err := newWrappedValidationError(wrappedErr)

		assert.EqualError(t, err, "datastore-validation: bar")

		var vErr *validationError
		assert.True(t, errors.As(err, &vErr))

		assert.True(t, errors.Is(err, &validationError{
			err: wrappedErr,
		}))
	})
}
