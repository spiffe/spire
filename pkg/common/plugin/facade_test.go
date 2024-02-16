package plugin_test

import (
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	facade = plugin.FixedFacade("name", "type", plugin.NullLogger())
)

func TestPrefixMessage(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		assert.Equal(t, "type(name): ohno", plugin.PrefixMessage(facade, "ohno"))
	})

	t.Run("with old prefix", func(t *testing.T) {
		assert.Equal(t, "type(name): ohno", plugin.PrefixMessage(facade, "name: ohno"))
	})

	t.Run("already prefixed", func(t *testing.T) {
		assert.Equal(t, "type(name): ohno", plugin.PrefixMessage(facade, "type(name): ohno"))
	})
}

func TestFacadeWrapErr(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.Nil(t, facade.WrapErr(nil))
	})

	t.Run("standard error without prefix", func(t *testing.T) {
		err := facade.WrapErr(ohnoError(""))
		assert.EqualError(t, err, "type(name): ohno")
		assert.True(t, errors.Is(err, ohnoError("")))
	})

	t.Run("standard error with old prefix prefixed", func(t *testing.T) {
		err := facade.WrapErr(ohnoError("name: "))
		assert.EqualError(t, err, "type(name): ohno")
		assert.True(t, errors.Is(err, ohnoError("name: ")))
	})

	t.Run("standard error already prefixed", func(t *testing.T) {
		err := facade.WrapErr(ohnoError("type(name): "))
		assert.EqualError(t, err, "type(name): ohno")
		assert.True(t, errors.Is(err, ohnoError("type(name): ")))
	})

	t.Run("grpc status without prefix", func(t *testing.T) {
		stIn := status.FromProto(&spb.Status{
			Code:    int32(codes.InvalidArgument),
			Message: "ohno",
			Details: []*anypb.Any{{TypeUrl: "fake"}},
		})

		stOut := status.Convert(facade.WrapErr(stIn.Err()))

		assert.Equal(t, stIn.Code(), stOut.Code())
		assert.Equal(t, stIn.Details(), stOut.Details())
		assert.Equal(t, "type(name): ohno", stOut.Message())
	})

	t.Run("grpc status with old prefix", func(t *testing.T) {
		stIn := status.FromProto(&spb.Status{
			Code:    int32(codes.InvalidArgument),
			Message: "name: ohno",
			Details: []*anypb.Any{{TypeUrl: "fake"}},
		})

		stOut := status.Convert(facade.WrapErr(stIn.Err()))
		assert.Equal(t, stIn.Code(), stOut.Code())
		assert.Equal(t, stIn.Details(), stOut.Details())
		assert.Equal(t, "type(name): ohno", stOut.Message())
	})

	t.Run("grpc status with prefix", func(t *testing.T) {
		stIn := status.FromProto(&spb.Status{
			Code:    int32(codes.InvalidArgument),
			Message: "type(name): ohno",
			Details: []*anypb.Any{{TypeUrl: "fake"}},
		})

		stOut := status.Convert(facade.WrapErr(stIn.Err()))

		assert.Equal(t, stIn.Code(), stOut.Code())
		assert.Equal(t, stIn.Details(), stOut.Details())
		assert.Equal(t, "type(name): ohno", stOut.Message())
	})
}

func TestFacadeError(t *testing.T) {
	st, ok := status.FromError(facade.Error(codes.Internal, "ohno"))
	require.True(t, ok, "error is not a gRPC status")
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "type(name): ohno", st.Message())
}

func TestFacadeErrorf(t *testing.T) {
	st, ok := status.FromError(facade.Errorf(codes.Internal, "%s", "ohno"))
	require.True(t, ok, "error is not a gRPC status")
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "type(name): ohno", st.Message())
}

type ohnoError string

func (prefix ohnoError) Error() string {
	return string(prefix) + "ohno"
}
