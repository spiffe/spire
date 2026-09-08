package errorutil_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/common/errorutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsCanceled(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
		},
		{
			name: "other error",
			err:  errors.New("oh no"),
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: true,
		},
		{
			name: "wrapped context canceled",
			err:  fmt.Errorf("wrapped: %w", context.Canceled),
			want: true,
		},
		{
			name: "gRPC context canceled",
			err:  status.FromContextError(context.Canceled).Err(),
			want: true,
		},
		{
			name: "wrapped gRPC canceled",
			err:  fmt.Errorf("wrapped: %w", status.Error(codes.Canceled, "canceled")),
			want: true,
		},
		{
			name: "other gRPC error",
			err:  status.Error(codes.Internal, "oh no"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, errorutil.IsCanceled(testCase.err))
		})
	}
}
