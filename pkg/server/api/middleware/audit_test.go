package middleware_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAgentSyncAuditMiddleware(t *testing.T) {
	for _, tt := range []struct {
		name       string
		fullMethod string
		filtered   bool
		streaming  bool
	}{
		{"bundle", bundlev1.Bundle_GetBundle_FullMethodName, true, false},
		{"federated bundle", bundlev1.Bundle_GetFederatedBundle_FullMethodName, true, false},
		{"authorized entries", entryv1.Entry_GetAuthorizedEntries_FullMethodName, true, false},
		{"entry sync", entryv1.Entry_SyncAuthorizedEntries_FullMethodName, true, true},
		{"bundle write", bundlev1.Bundle_BatchSetFederatedBundle_FullMethodName, false, false},
		{"entry write", entryv1.Entry_BatchCreateEntry_FullMethodName, false, false},
		{"other read", bundlev1.Bundle_ListFederatedBundles_FullMethodName, false, false},
		{"same method on another service", "/other.Bundle/GetBundle", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []struct {
				name    string
				exclude bool
			}{
				{"default", false},
				{"exclude reads", true},
			} {
				t.Run(mode.name, func(t *testing.T) {
					for _, result := range []struct {
						name string
						err  error
					}{
						{"success", nil},
						{"failure", status.Error(codes.Unavailable, "datastore unavailable")},
					} {
						t.Run(result.name, func(t *testing.T) {
							log, hook := test.NewNullLogger()
							chain := middleware.Chain(middleware.WithLogger(log), middleware.WithAuditLog(false, mode.exclude))
							auditRequest := func(ctx context.Context) error {
								if result.err == nil {
									rpccontext.AuditRPCWithFields(ctx, logrus.Fields{"fixture": "agent-sync-read"})
								}
								return result.err
							}

							var err error
							if tt.streaming {
								err = middleware.StreamInterceptor(chain)(nil, auditServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{FullMethod: tt.fullMethod}, func(_ any, stream grpc.ServerStream) error {
									return auditRequest(stream.Context())
								})
							} else {
								_, err = middleware.UnaryInterceptor(chain)(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: tt.fullMethod}, func(ctx context.Context, _ any) (any, error) {
									return nil, auditRequest(ctx)
								})
							}
							require.Equal(t, result.err, err)

							var entries []*logrus.Entry
							for _, entry := range hook.AllEntries() {
								if entry.Data[telemetry.Type] == "audit" {
									entries = append(entries, entry)
								}
							}
							if mode.exclude && tt.filtered && result.err == nil {
								require.Empty(t, entries)
								return
							}
							require.Len(t, entries, 1)
							require.Equal(t, "API accessed", entries[0].Message)
							if result.err != nil {
								require.Equal(t, "error", entries[0].Data[telemetry.Status])
								require.Equal(t, codes.Unavailable, entries[0].Data[telemetry.StatusCode])
								require.Equal(t, "datastore unavailable", entries[0].Data[telemetry.StatusMessage])
							} else {
								require.Equal(t, "success", entries[0].Data[telemetry.Status])
								require.Equal(t, "agent-sync-read", entries[0].Data["fixture"])
							}
						})
					}
				})
			}
		})
	}
}

type auditServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s auditServerStream) Context() context.Context {
	return s.ctx
}
