package middleware_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestWithAuthorizationPreprocess(t *testing.T) {
	id := spiffeid.Must("example.org", "workload")
	x509SVID := &x509.Certificate{URIs: []*url.URL{id.URL()}}

	unixPeer := &peer.Peer{
		Addr: &net.UnixAddr{
			Net:  "unix",
			Name: "/not/a/real/path.sock",
		},
	}

	tlsPeer := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 1,
		},
	}

	mtlsPeer := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("2.2.2.2"),
			Port: 2,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{x509SVID},
			},
		},
	}

	for _, tt := range []struct {
		name          string
		fullMethod    string
		peer          *peer.Peer
		authorizerErr error
		expectCode    codes.Code
		expectMsg     string
		expectLogs    []spiretest.LogEntry
	}{
		{
			name:       "local caller",
			fullMethod: fakeFullMethod,
			peer:       unixPeer,
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Authorizer called",
				},
			},
		},
		{
			name:       "remote caller without ID",
			fullMethod: fakeFullMethod,
			peer:       tlsPeer,
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Authorizer called",
					Data: logrus.Fields{
						"caller-addr": "1.1.1.1:1",
					},
				},
			},
		},
		{
			name:       "remote caller with ID",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			expectCode: codes.OK,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Authorizer called",
					Data: logrus.Fields{
						"caller-addr": "2.2.2.2:2",
						"caller-id":   "spiffe://example.org/workload",
					},
				},
			},
		},
		{
			name:       "no peer",
			fullMethod: fakeFullMethod,
			peer:       nil,
			expectCode: codes.Internal,
			expectMsg:  "no peer information available",
		},
		{
			name:       "unrecognized method",
			fullMethod: "/some.Service/WhatInTheWorld",
			peer:       unixPeer,
			expectCode: codes.Internal,
			expectMsg:  `authorization misconfigured for "/some.Service/WhatInTheWorld"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Authorization misconfigured; this is a bug",
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			authorizer := authorizerFn(func(ctx context.Context) (context.Context, error) {
				// Assert the context is set and has the caller information.
				require.NotNil(t, ctx, "authorizer was not called")
				assert.Equal(t, rpccontext.CallerAddr(ctx), tt.peer.Addr)

				// Logging here allows us to assert that the right fields were
				// added to the logger.
				rpccontext.Logger(ctx).Info("Authorizer called")

				// Wrap the returned context so we can assert that the wrapped
				// context was returned from the middleware.
				return wrapContext(ctx), tt.authorizerErr
			})

			// Set up an authorization middleware with one method.
			m := middleware.WithAuthorization(map[string]middleware.Authorizer{
				fakeFullMethod: authorizer,
			})

			// Set up the incoming context with a logger and optionally a peer.
			log, hook := test.NewNullLogger()
			ctxIn := rpccontext.WithLogger(context.Background(), log)
			if tt.peer != nil {
				ctxIn = peer.NewContext(ctxIn, tt.peer)
			}

			ctxOut, err := m.Preprocess(ctxIn, tt.fullMethod)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)

			// Assert the properties of the context returned by Preprocess.
			if tt.expectCode != codes.OK {
				assert.Nil(t, ctxOut, "returned context should have not been set on preprocess failure")
				return
			}
			require.NotNil(t, ctxOut, "returned context should have been non-nil on success")
			assert.Equal(t, 1, wrapCount(ctxOut), "returned context was not wrapped by authorizer")
		})
	}
}

func TestWithAuthorizationPostprocess(t *testing.T) {
	// Postprocess doesn't do anything. Let's just make sure it doesn't panic.
	m := middleware.WithAuthorization(nil)
	m.Postprocess(context.Background(), "", false, nil)
	m.Postprocess(context.Background(), "", true, errors.New("ohno"))
}

type authorizerFn func(ctx context.Context) (context.Context, error)

func (fn authorizerFn) Name() string {
	return "fake"
}

func (fn authorizerFn) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	return fn(ctx)
}
