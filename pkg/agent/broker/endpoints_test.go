package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	brokerapi "github.com/spiffe/spire/pkg/agent/broker/api"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type staticSVIDSource struct {
	svid *x509svid.SVID
}

func (s staticSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	return s.svid, nil
}

// brokerListenerTLSConfig mirrors the TLS setup in Endpoints.ListenAndServe so
// profile application can be tested without duplicating production helpers.
func brokerListenerTLSConfig(svidSource x509svid.Source, bundleSource x509bundle.Source, brokerIDs []spiffeid.ID, policy tlspolicy.Policy) (*tls.Config, error) {
	tlsConfig := tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeOneOf(brokerIDs...))
	tlsConfig.SessionTicketsDisabled = true
	if err := tlspolicy.ApplyPolicy(tlsConfig, policy, tlspolicy.WithServerTLSConfig()); err != nil {
		return nil, fmt.Errorf("failed to apply TLS policy: %w", err)
	}
	return tlsConfig, nil
}

func TestBrokerListenerWithTLSPolicy(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	agentSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/agent"))
	brokerID := spiffeid.RequireFromPath(td, "/broker")

	policy, err := tlspolicy.NewPolicy(false, &tlspolicy.TLSConfig{
		MinTLSVersion: "VersionTLS13",
		CipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		CurvePreferences: []string{
			"X25519MLKEM768",
			"secp256r1",
		},
	})
	require.NoError(t, err)

	tlsConfig, err := brokerListenerTLSConfig(
		staticSVIDSource{svid: agentSVID},
		ca.X509Bundle(),
		[]spiffeid.ID{brokerID},
		policy,
	)
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.NotEmpty(t, tlsConfig.CipherSuites)
	require.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256}, tlsConfig.CurvePreferences)
}

func TestBrokerListenerWithInvalidTLSPolicy(t *testing.T) {
	_, err := tlspolicy.NewPolicy(false, &tlspolicy.TLSConfig{
		MinTLSVersion: "not-a-version",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid minTLSVersion")
}

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
		},
	}, policies)
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
