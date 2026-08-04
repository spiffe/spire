package api

import (
	"context"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	k8sType = "type.googleapis.com/spiffe.broker.KubernetesObjectReference"
	pidType = "type.googleapis.com/spiffe.broker.PIDReference"

	// nonCanonicalSelectorType is a SelectorReference under a non-canonical
	// type URL prefix. anypb resolves a type URL by the segment after the last
	// "/", so this unmarshals into a SelectorReference exactly as the canonical
	// URL does, and must be gated identically.
	nonCanonicalSelectorType = "example.com/spiffe.broker.SelectorReference"
)

func udsContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
	})
}

func tcpContext() context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
	})
}

func ref(typeURL string) *anypb.Any {
	if typeURL == "" {
		return nil
	}
	return &anypb.Any{TypeUrl: typeURL}
}

func TestIsTCPCaller(t *testing.T) {
	assert.True(t, isTCPCaller(tcpContext()))
	assert.False(t, isTCPCaller(udsContext()))
	assert.False(t, isTCPCaller(context.Background()))
}

func TestAuthorizeReferenceType(t *testing.T) {
	caller := spiffeid.RequireFromString("spiffe://example.org/broker")
	other := spiffeid.RequireFromString("spiffe://example.org/other")

	for _, tt := range []struct {
		name        string
		byCaller    map[spiffeid.ID]ReferenceTypePolicy
		selByCaller map[spiffeid.ID]SelectorAssertionPolicy
		ctx         context.Context
		caller      spiffeid.ID
		ref         *anypb.Any
		expectCode  codes.Code
	}{
		{
			name:       "nil reference is rejected before any gate",
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(""),
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "empty type url is rejected",
			ctx:        udsContext(),
			caller:     caller,
			ref:        &anypb.Any{},
			expectCode: codes.InvalidArgument,
		},
		{
			name: "caller present and type allowed over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.OK,
		},
		{
			name: "caller present and type not allowed",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "caller absent from map behaves as wildcard over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{other: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "TCP caller allowed when reference type opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {AllowOverTCP: true}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.OK,
		},
		{
			name: "TCP caller denied when reference type does not opt in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{k8sType: {}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.PermissionDenied,
		},
		{
			name:       "TCP caller denied when caller has no policy",
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(k8sType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "wildcard allows any type over UDS",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "wildcard allows any type over TCP when it opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny:        true,
				AllowAnyOverTCP: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.OK,
		},
		{
			name: "wildcard denies TCP by default",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(pidType),
			expectCode: codes.PermissionDenied,
		},
		{
			// The wildcard means "any type my attestor stack can resolve". A
			// selector reference is resolved by nothing, so inheriting it from
			// the wildcard would silently escalate existing wildcard brokers.
			name: "wildcard does not grant the selector reference",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(SelectorReferenceTypeURL),
			expectCode: codes.PermissionDenied,
		},
		{
			// The gate matches on protobuf message name, not the raw type URL,
			// so a non-canonical prefix cannot smuggle a selector reference
			// past the wildcard exclusion.
			name: "wildcard does not grant a non-canonically prefixed selector reference",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny: true,
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(nonCanonicalSelectorType),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "selector reference allowed over UDS when explicitly granted",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{SelectorReferenceTypeURL: {}},
			}},
			selByCaller: map[spiffeid.ID]SelectorAssertionPolicy{caller: {
				AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(SelectorReferenceTypeURL),
			expectCode: codes.OK,
		},
		{
			// TCP for asserted selectors is governed by allow_over_tcp on the
			// explicitly named entry, exactly as for any other reference type.
			name: "selector reference denied over TCP without allow_over_tcp",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{SelectorReferenceTypeURL: {}},
			}},
			selByCaller: map[spiffeid.ID]SelectorAssertionPolicy{caller: {
				AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(SelectorReferenceTypeURL),
			expectCode: codes.PermissionDenied,
		},
		{
			name: "selector reference allowed over TCP when the entry opts in",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				Types: map[string]ReferenceTypeAccess{SelectorReferenceTypeURL: {AllowOverTCP: true}},
			}},
			selByCaller: map[spiffeid.ID]SelectorAssertionPolicy{caller: {
				AllowedSelectorTypes: map[string]struct{}{"k8s_psat": {}},
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(SelectorReferenceTypeURL),
			expectCode: codes.OK,
		},
		{
			// The wildcard grants TCP to types it covers, but must not reach the
			// selector reference even when AllowAnyOverTCP is set.
			name: "wildcard with TCP does not grant selector reference over TCP",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{caller: {
				AllowAny:        true,
				AllowAnyOverTCP: true,
			}},
			ctx:        tcpContext(),
			caller:     caller,
			ref:        ref(SelectorReferenceTypeURL),
			expectCode: codes.PermissionDenied,
		},
		{
			// The fail-open-over-UDS default for unconfigured callers must not
			// extend to the selector reference.
			name: "selector reference denied when caller has no policy",
			byCaller: map[spiffeid.ID]ReferenceTypePolicy{other: {
				AllowAny: true,
			}},
			ctx:        udsContext(),
			caller:     caller,
			ref:        ref(SelectorReferenceTypeURL),
			expectCode: codes.PermissionDenied,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{
				AllowedReferenceTypesByCaller: tt.byCaller,
				SelectorAssertionByCaller:     tt.selByCaller,
			})
			err := s.authorizeReferenceType(tt.ctx, tt.caller, tt.ref)
			if tt.expectCode == codes.OK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.expectCode, status.Code(err))
		})
	}
}
