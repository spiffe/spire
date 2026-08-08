package broker

import (
	"context"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	brokerapi "github.com/spiffe/spire/pkg/agent/broker/api"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestRestrictReflectionToUDS(t *testing.T) {
	for _, tt := range []struct {
		name       string
		fullMethod string
		addr       net.Addr
		expectCode codes.Code
	}{
		{
			name:       "non-reflection method without peer is allowed",
			fullMethod: "/spiffe.broker.API/FetchX509SVID",
			expectCode: codes.OK,
		},
		{
			name:       "reflection over UDS is allowed",
			fullMethod: "/" + middleware.ServerReflectionServiceName + "/ServerReflectionInfo",
			addr:       &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
			expectCode: codes.OK,
		},
		{
			name:       "reflection v1alpha over UDS is allowed",
			fullMethod: "/" + middleware.ServerReflectionV1AlphaServiceName + "/ServerReflectionInfo",
			addr:       &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"},
			expectCode: codes.OK,
		},
		{
			name:       "reflection over TCP is denied",
			fullMethod: "/" + middleware.ServerReflectionServiceName + "/ServerReflectionInfo",
			addr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081},
			expectCode: codes.PermissionDenied,
		},
		{
			name:       "reflection without peer is internal",
			fullMethod: "/" + middleware.ServerReflectionServiceName + "/ServerReflectionInfo",
			expectCode: codes.Internal,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.addr != nil {
				ctx = peer.NewContext(ctx, &peer.Peer{Addr: tt.addr})
			}

			_, err := restrictReflectionToUDS(ctx, tt.fullMethod, nil)
			if tt.expectCode == codes.OK {
				require.NoError(t, err)
				return
			}
			require.Equal(t, tt.expectCode, status.Code(err))
		})
	}
}

func TestBuildAllowedReferenceTypeMap(t *testing.T) {
	brokerID := spiffeid.RequireFromString("spiffe://example.org/broker")
	wildcardID := spiffeid.RequireFromString("spiffe://example.org/wildcard")
	mixedID := spiffeid.RequireFromString("spiffe://example.org/mixed")
	k8sType := "type.googleapis.com/spiffe.broker.KubernetesObjectReference"
	pidType := "type.googleapis.com/spiffe.broker.WorkloadPIDReference"

	policies := buildAllowedReferenceTypeMap([]Broker{
		{
			ID: brokerID.String(),
			AllowedReferenceTypes: []AllowedReferenceType{
				{TypeURL: k8sType, AllowOverTCP: true},
				{TypeURL: pidType},
			},
		},
		{
			ID: "not a spiffe id",
			AllowedReferenceTypes: []AllowedReferenceType{
				{TypeURL: k8sType, AllowOverTCP: true},
			},
		},
		{
			ID: wildcardID.String(),
			AllowedReferenceTypes: []AllowedReferenceType{
				{TypeURL: "*", AllowOverTCP: true},
			},
		},
		{
			ID: mixedID.String(),
			AllowedReferenceTypes: []AllowedReferenceType{
				{TypeURL: "*", AllowOverTCP: true},
				{TypeURL: SelectorReferenceTypeURL},
			},
			SelectorAssertion: &SelectorAssertion{
				AllowedSelectorTypes: []string{"k8s_psat"},
			},
		},
	})

	require.Equal(t, map[spiffeid.ID]brokerapi.ReferenceTypePolicy{
		brokerID: {
			Types: map[string]brokerapi.ReferenceTypeAccess{
				k8sType: {AllowOverTCP: true},
				pidType: {},
			},
		},
		wildcardID: {
			AllowAny:        true,
			AllowAnyOverTCP: true,
			Types:           map[string]brokerapi.ReferenceTypeAccess{},
		},
		// The wildcard must not swallow explicitly granted types: a broker can
		// hold "*" for attestable references and separately be granted the
		// selector reference, which "*" deliberately does not cover.
		mixedID: {
			AllowAny:        true,
			AllowAnyOverTCP: true,
			Types: map[string]brokerapi.ReferenceTypeAccess{
				SelectorReferenceTypeURL: {},
			},
		},
	}, policies)
}

func TestBuildSelectorAssertionMap(t *testing.T) {
	assertingID := spiffeid.RequireFromString("spiffe://example.org/asserting")
	plainID := spiffeid.RequireFromString("spiffe://example.org/plain")

	policies := buildSelectorAssertionMap([]Broker{
		{
			ID: assertingID.String(),
			SelectorAssertion: &SelectorAssertion{
				AllowedSelectorTypes: []string{"k8s_psat", "github_actions"},
				MaxSelectors:         32,
			},
		},
		{
			// No selector_assertion block: absent from the map entirely, which
			// the service treats as "may not assert selectors".
			ID: plainID.String(),
		},
		{
			ID: "not a spiffe id",
			SelectorAssertion: &SelectorAssertion{
				AllowedSelectorTypes: []string{"k8s_psat"},
			},
		},
	})

	require.Equal(t, map[spiffeid.ID]brokerapi.SelectorAssertionPolicy{
		assertingID: {
			AllowedSelectorTypes: map[string]struct{}{
				"k8s_psat":       {},
				"github_actions": {},
			},
			MaxSelectors: 32,
		},
	}, policies)
}

func TestBuildSelectorAssertionMapDefaultsMaxSelectors(t *testing.T) {
	assertingID := spiffeid.RequireFromString("spiffe://example.org/asserting")

	policies := buildSelectorAssertionMap([]Broker{
		{
			ID: assertingID.String(),
			SelectorAssertion: &SelectorAssertion{
				AllowedSelectorTypes: []string{"k8s_psat"},
			},
		},
	})

	require.Equal(t, brokerapi.DefaultMaxAssertedSelectors, policies[assertingID].MaxSelectors)
}

// TestPreprocessorChain exercises restrictReflectionToUDS and
// verifyBrokerSecurityHeader composed in the same order as the gRPC
// interceptor chain, since the security header is enforced for every
// method including reflection over UDS.
func TestPreprocessorChain(t *testing.T) {
	reflectionMethod := "/" + middleware.ServerReflectionServiceName + "/ServerReflectionInfo"
	udsAddr := &net.UnixAddr{Name: "/tmp/broker.sock", Net: "unix"}
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}

	for _, tt := range []struct {
		name       string
		fullMethod string
		addr       net.Addr
		header     bool
		expectCode codes.Code
	}{
		{
			name:       "reflection over UDS without header is denied",
			fullMethod: reflectionMethod,
			addr:       udsAddr,
			header:     false,
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "reflection over UDS with header is allowed",
			fullMethod: reflectionMethod,
			addr:       udsAddr,
			header:     true,
			expectCode: codes.OK,
		},
		{
			name:       "reflection over TCP is denied before header check",
			fullMethod: reflectionMethod,
			addr:       tcpAddr,
			header:     true,
			expectCode: codes.PermissionDenied,
		},
		{
			name:       "non-reflection method without header is denied",
			fullMethod: "/spiffe.broker.API/FetchX509SVID",
			addr:       udsAddr,
			header:     false,
			expectCode: codes.InvalidArgument,
		},
		{
			name:       "non-reflection method with header is allowed",
			fullMethod: "/spiffe.broker.API/FetchX509SVID",
			addr:       udsAddr,
			header:     true,
			expectCode: codes.OK,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: tt.addr})
			if tt.header {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("broker.spiffe.io", "true"))
			}

			ctx, err := restrictReflectionToUDS(ctx, tt.fullMethod, nil)
			if err == nil {
				_, err = verifyBrokerSecurityHeader(ctx, tt.fullMethod, nil)
			}

			if tt.expectCode == codes.OK {
				require.NoError(t, err)
				return
			}
			require.Equal(t, tt.expectCode, status.Code(err))
		})
	}
}
