package endpoints

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func TestWrapWithDeprecationLogging(t *testing.T) {
	origClk := deprecationClk
	defer func() {
		deprecationClk = origClk
	}()

	expectErr := errors.New("ohno")
	serverStream := struct{ grpc.ServerStream }{}
	unaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		assert.Equal(t, context.Background(), ctx)
		assert.Equal(t, "req", req)
		return "resp", expectErr
	}

	streamHandler := func(srv interface{}, ss grpc.ServerStream) error {
		assert.Equal(t, "srv", srv)
		assert.Equal(t, serverStream, ss)
		return expectErr
	}

	for _, tt := range []struct {
		name       string
		fullMethod string
		expectLogs []spiretest.LogEntry
	}{
		{
			fullMethod: "/spire.api.registration.Registration/FetchEntry",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "This API is deprecated and will be removed in a future release (see https://github.com/spiffe/spire/blob/master/doc/migrating_registration_api_clients.md)",
					Data: logrus.Fields{
						"method": "/spire.api.registration.Registration/FetchEntry",
					},
				},
			},
		},
		{
			fullMethod: "/spire.api.node.Node/FetchBundle",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "This API is deprecated and will be removed in a future release",
					Data: logrus.Fields{
						"method": "/spire.api.node.Node/FetchBundle",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			clk := clock.NewMock(t)
			deprecationClk = clk

			log, hook := test.NewNullLogger()
			streamServerInfo := &grpc.StreamServerInfo{FullMethod: tt.fullMethod}
			unaryServerInfo := &grpc.UnaryServerInfo{FullMethod: tt.fullMethod}
			unaryInterceptor, streamInterceptor := wrapWithDeprecationLogging(log,
				func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
					// Assert that args are forwarded through the wrapper
					assert.Equal(t, unaryServerInfo, info)
					return handler(ctx, req)
				},
				func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
					// Assert that args are forwarded through the wrapper
					assert.Equal(t, streamServerInfo, info)
					return handler(srv, ss)
				})

			callUnary := func(expectLogs []spiretest.LogEntry) {
				hook.Reset()
				resp, err := unaryInterceptor(context.Background(), "req", unaryServerInfo, unaryHandler)
				assert.Equal(t, "resp", resp)
				assert.Equal(t, expectErr, err)
				spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
			}

			callStream := func(expectLogs []spiretest.LogEntry) {
				hook.Reset()
				err := streamInterceptor("srv", serverStream, streamServerInfo, streamHandler)
				assert.Equal(t, expectErr, err)
				spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
			}

			// Assert first unary call logs, second does not, and third does
			// after advancing the clock.
			clk.Add(deprecationLogEvery)
			callUnary(tt.expectLogs)
			callUnary(nil)
			clk.Add(deprecationLogEvery)
			callUnary(tt.expectLogs)

			// Assert first stream call logs, second does not, and third does
			// after advancing the clock.
			clk.Add(deprecationLogEvery)
			callStream(tt.expectLogs)
			callStream(nil)
			clk.Add(deprecationLogEvery)
			callStream(tt.expectLogs)
		})
	}
}
