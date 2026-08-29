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
		name       string
		byCaller   map[spiffeid.ID]ReferenceTypePolicy
		ctx        context.Context
		caller     spiffeid.ID
		ref        *anypb.Any
		expectCode codes.Code
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Config{
				AllowedReferenceTypesByCaller: tt.byCaller,
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
