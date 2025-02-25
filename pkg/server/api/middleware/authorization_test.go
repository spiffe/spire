package middleware_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/authpolicy"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/runtime/protoiface"
)

func TestWithAuthorizationPreprocess(t *testing.T) {
	workloadID := spiffeid.RequireFromString("spiffe://example.org/workload")
	x509SVID := &x509.Certificate{URIs: []*url.URL{workloadID.URL()}}

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

	adminX509SVID := &x509.Certificate{URIs: []*url.URL{adminID.URL()}}
	adminPeer := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("2.2.2.2"),
			Port: 2,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{adminX509SVID},
			},
		},
	}

	staticAdminX509SVID := &x509.Certificate{URIs: []*url.URL{staticAdminID.URL()}}
	staticAdminPeer := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("2.2.2.2"),
			Port: 2,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{staticAdminX509SVID},
			},
		},
	}

	downstreamX509SVID := &x509.Certificate{URIs: []*url.URL{downstreamID.URL()}}
	downstreamPeer := &peer.Peer{
		Addr: &net.TCPAddr{
			IP:   net.ParseIP("2.2.2.2"),
			Port: 2,
		},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				HandshakeComplete: true,
				PeerCertificates:  []*x509.Certificate{downstreamX509SVID},
			},
		},
	}

	for _, tt := range []struct {
		name            string
		request         any
		fullMethod      string
		peer            *peer.Peer
		rego            string
		agentAuthorizer middleware.AgentAuthorizer
		entryFetcher    middleware.EntryFetcherFunc
		adminIDs        []spiffeid.ID
		authorizerErr   error
		expectCode      codes.Code
		expectMsg       string
		expectDetails   []*types.PermissionDeniedDetails
	}{
		{
			name:       "basic allow test",
			fullMethod: fakeFullMethod,
			peer:       unixPeer,
			rego: simpleRego(map[string]bool{
				"allow": true,
			}),
			expectCode: codes.OK,
		},
		{
			name:       "basic deny test",
			fullMethod: fakeFullMethod,
			peer:       unixPeer,
			rego: simpleRego(map[string]bool{
				"allow": false,
			}),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "allow_if_local local caller test",
			fullMethod: fakeFullMethod,
			peer:       unixPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_local": true,
			}),
			expectCode: codes.OK,
		},
		{
			name:       "allow_if_local non-local caller test",
			fullMethod: fakeFullMethod,
			peer:       tlsPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_local": true,
			}),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "allow_if_admin admin caller test",
			fullMethod: fakeFullMethod,
			peer:       adminPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_admin": true,
			}),
			expectCode: codes.OK,
		},
		{
			name:       "allow_if_admin static admin caller test",
			fullMethod: fakeFullMethod,
			peer:       staticAdminPeer,
			adminIDs:   []spiffeid.ID{staticAdminID},
			rego: simpleRego(map[string]bool{
				"allow_if_admin": true,
			}),
			expectCode: codes.OK,
		},
		{
			name:       "allow_if_admin non-admin caller test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_admin": true,
			}),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "allow_if_downstream downstream caller test",
			fullMethod: fakeFullMethod,
			peer:       downstreamPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_downstream": true,
			}),
			expectCode: codes.OK,
		},
		{
			name:       "allow_if_downstream non-downstream caller test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_downstream": true,
			}),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "allow_if_agent agent caller test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_agent": true,
			}),
			agentAuthorizer: yesAgentAuthorizer,
			expectCode:      codes.OK,
		},
		{
			name:       "allow_if_agent non-agent caller test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_agent": true,
			}),
			agentAuthorizer: noAgentAuthorizer,
			expectCode:      codes.PermissionDenied,
			expectMsg:       fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "allow_if_agent non-agent caller test with details",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_agent": true,
			}),
			agentAuthorizer: &testAgentAuthorizer{
				isAgent: false,
				details: []protoiface.MessageV1{
					&types.PermissionDeniedDetails{
						Reason: types.PermissionDeniedDetails_AGENT_BANNED,
					},
					// Add a custom details that will be ignored
					&types.Bundle{TrustDomain: "td.com"},
				},
			},
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
			expectDetails: []*types.PermissionDeniedDetails{
				{
					Reason: types.PermissionDeniedDetails_AGENT_BANNED,
				},
			},
		},
		{
			name:       "check passing of caller id positive test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego:       condCheckRego(fmt.Sprintf("input.caller == \"%s\"", workloadID.String())),
			expectCode: codes.OK,
		},
		{
			name:       "check passing of caller id negative test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego:       condCheckRego("input.caller == \"abc\""),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:            "check passing of full method positive test",
			fullMethod:      fakeFullMethod,
			peer:            mtlsPeer,
			rego:            condCheckRego(fmt.Sprintf("input.full_method == \"%s\"", fakeFullMethod)),
			agentAuthorizer: yesAgentAuthorizer,
			expectCode:      codes.OK,
		},
		{
			name:       "check passing of full method negative test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			rego:       condCheckRego("input.full_method == \"notmethod\""),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "check passing of request positive test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			request: map[string]string{
				"foo": "bar",
			},
			rego:            condCheckRego("input.req.foo == \"bar\""),
			agentAuthorizer: yesAgentAuthorizer,
			expectCode:      codes.OK,
		},
		{
			name:       "check passing of request negative test",
			fullMethod: fakeFullMethod,
			peer:       mtlsPeer,
			request: map[string]string{
				"foo": "not bar",
			},
			rego:       condCheckRego("input.req.foo == \"bar\""),
			expectCode: codes.PermissionDenied,
			expectMsg:  fmt.Sprintf("authorization denied for method %s", fakeFullMethod),
		},
		{
			name:       "no peer",
			fullMethod: fakeFullMethod,
			peer:       nil,
			expectCode: codes.Internal,
			rego:       simpleRego(map[string]bool{}),
			expectMsg:  "no peer information available",
		},
		{
			name:       "entry fetcher error is handled",
			fullMethod: fakeFullMethod,
			peer:       downstreamPeer,
			rego: simpleRego(map[string]bool{
				"allow_if_downstream": true,
			}),
			entryFetcher: func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
				return nil, errors.New("entry fetcher error")
			},
			expectCode: codes.Internal,
			expectMsg:  "failed to fetch caller entries: entry fetcher error",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			policyEngine, err := authpolicy.NewEngineFromRego(ctx, tt.rego, inmem.NewFromObject(map[string]any{}), ast.RegoV1)
			require.NoError(t, err, "failed to initialize policy engine")

			// Set up an authorization middleware with one method.
			if tt.agentAuthorizer == nil {
				tt.agentAuthorizer = noAgentAuthorizer
			}

			m := middleware.WithAuthorization(policyEngine, entryFetcherForTest(tt.entryFetcher), tt.agentAuthorizer, tt.adminIDs)

			// Set up the incoming context with a logger and optionally a peer.
			log, _ := test.NewNullLogger()
			ctxIn := rpccontext.WithLogger(ctx, log)
			if tt.peer != nil {
				ctxIn = peer.NewContext(ctxIn, tt.peer)
			}

			ctxOut, err := m.Preprocess(ctxIn, tt.fullMethod, tt.request)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)

			// Get Status to validate details
			st, ok := status.FromError(err)
			require.True(t, ok)

			var statusDetails []*types.PermissionDeniedDetails
			for _, eachDetail := range st.Details() {
				message, ok := eachDetail.(*types.PermissionDeniedDetails)
				require.True(t, ok, "unexpected status detail type: %T", message)
				statusDetails = append(statusDetails, message)
			}

			switch {
			case len(tt.expectDetails) > 0:
				spiretest.RequireProtoListEqual(t, tt.expectDetails, statusDetails)
			case len(statusDetails) > 0:
				require.Fail(t, "no status details expected")
			}

			// Assert the properties of the context returned by Preprocess.
			if tt.expectCode != codes.OK {
				assert.Nil(t, ctxOut, "returned context should have not been set on preprocess failure")
				return
			}
			require.NotNil(t, ctxOut, "returned context should have been non-nil on success")
		})
	}
}

func TestWithAuthorizationPostprocess(t *testing.T) {
	// Postprocess doesn't do anything. Let's just make sure it doesn't panic.
	ctx := context.Background()
	policyEngine, err := authpolicy.DefaultAuthPolicy(ctx)
	require.NoError(t, err, "failed to initialize policy engine")
	m := middleware.WithAuthorization(policyEngine, entryFetcher, yesAgentAuthorizer, nil)

	m.Postprocess(context.Background(), "", false, nil)
	m.Postprocess(context.Background(), "", true, errors.New("ohno"))
}

var (
	td           = spiffeid.RequireTrustDomainFromString("example.org")
	adminID      = spiffeid.RequireFromPath(td, "/admin")
	adminEntries = []*types.Entry{
		{Id: "1", Admin: true},
		{Id: "2"},
	}

	staticAdminID = spiffeid.RequireFromPath(td, "/static-admin")

	nonAdminID = spiffeid.RequireFromPath(td, "/non-admin")

	nonAdminEntries = []*types.Entry{
		{Id: "3"},
	}

	downstreamID      = spiffeid.RequireFromPath(td, "/downstream")
	downstreamEntries = []*types.Entry{
		{Id: "1", Downstream: true},
		{Id: "2"},
	}

	nonDownstreamID      = spiffeid.RequireFromPath(td, "/non-downstream")
	nonDownstreamEntries = []*types.Entry{
		{Id: "3"},
	}

	regEntries = []*types.Entry{
		{Id: "3"},
	}

	entryFetcher = middleware.EntryFetcherFunc(
		func(ctx context.Context, id spiffeid.ID) ([]*types.Entry, error) {
			switch id {
			case adminID:
				return adminEntries, nil
			case nonAdminID:
				return nonAdminEntries, nil
			case downstreamID:
				return downstreamEntries, nil
			case nonDownstreamID:
				return nonDownstreamEntries, nil
			default:
				return regEntries, nil
			}
		},
	)

	yesAgentAuthorizer = &testAgentAuthorizer{isAgent: true}
	noAgentAuthorizer  = &testAgentAuthorizer{isAgent: false}
)

type testAgentAuthorizer struct {
	isAgent bool
	details []protoiface.MessageV1
}

func (a *testAgentAuthorizer) AuthorizeAgent(context.Context, spiffeid.ID, *x509.Certificate) error {
	if a.isAgent {
		return nil
	}
	st := status.New(codes.PermissionDenied, "not agent")
	if a.details != nil {
		var err error
		st, err = st.WithDetails(a.details...)
		if err != nil {
			return err
		}
	}

	return st.Err()
}

func entryFetcherForTest(replace middleware.EntryFetcherFunc) middleware.EntryFetcherFunc {
	if replace != nil {
		return replace
	}

	return entryFetcher
}

func simpleRego(m map[string]bool) string {
	regoTemplate := `
    package spire
    result = {
      "allow": %t,
      "allow_if_admin": %t,
      "allow_if_local": %t,
      "allow_if_downstream": %t,
      "allow_if_agent": %t
    }`

	return fmt.Sprintf(regoTemplate, m["allow"], m["allow_if_admin"], m["allow_if_local"], m["allow_if_downstream"], m["allow_if_agent"])
}

func condCheckRego(cond string) string {
	regoTemplate := `
    package spire
    result = {
      "allow": allow,
      "allow_if_admin": false,
      "allow_if_local": false,
      "allow_if_downstream": false,
      "allow_if_agent": false
    }
    default allow = false
    
    allow=true if {
        %s
    }
    `
	fmt.Println(fmt.Sprintf(regoTemplate, cond))
	return fmt.Sprintf(regoTemplate, cond)
}
