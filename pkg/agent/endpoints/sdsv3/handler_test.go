package sdsv3

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	tdBundle = spiffebundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("domain.test"), []*x509.Certificate{{
		Raw: []byte("BUNDLE"),
	}})
	tdCustomValidationConfig, _ = anypb.New(&tls_v3.SPIFFECertValidatorConfig{
		TrustDomains: []*tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			{
				Name: "domain.test",
				TrustBundle: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	})
	tdValidationContext = &tls_v3.Secret{
		Name: "spiffe://domain.test",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	}
	tdValidationContextSpiffeValidator = &tls_v3.Secret{
		Name: "spiffe://domain.test",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: tdCustomValidationConfig,
				},
			},
		},
	}
	tdValidationContext2SpiffeValidator = &tls_v3.Secret{
		Name: "ROOTCA",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: tdCustomValidationConfig,
				},
			},
		},
	}

	tdValidationContext3 = &tls_v3.Secret{
		Name: "ALL",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	}

	fedBundle = spiffebundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("otherdomain.test"), []*x509.Certificate{{
		Raw: []byte("FEDBUNDLE"),
	}})
	fedCustomValidationConfig, _ = anypb.New(&tls_v3.SPIFFECertValidatorConfig{
		TrustDomains: []*tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			{
				Name: "otherdomain.test",
				TrustBundle: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nRkVEQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	})
	fedValidationContext = &tls_v3.Secret{
		Name: "spiffe://otherdomain.test",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				TrustedCa: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nRkVEQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	}
	fedValidationContextSpiffeValidator = &tls_v3.Secret{
		Name: "spiffe://otherdomain.test",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: fedCustomValidationConfig,
				},
			},
		},
	}

	allBundlesCustomValidationConfig, _ = anypb.New(&tls_v3.SPIFFECertValidatorConfig{
		TrustDomains: []*tls_v3.SPIFFECertValidatorConfig_TrustDomain{
			{
				Name: "domain.test",
				TrustBundle: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
			{
				Name: "otherdomain.test",
				TrustBundle: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nRkVEQlVORExF\n-----END CERTIFICATE-----\n"),
					},
				},
			},
		},
	})
	allBundlesValidationContext = &tls_v3.Secret{
		Name: "ALL",
		Type: &tls_v3.Secret_ValidationContext{
			ValidationContext: &tls_v3.CertificateValidationContext{
				CustomValidatorConfig: &core_v3.TypedExtensionConfig{
					Name:        "envoy.tls.cert_validator.spiffe",
					TypedConfig: allBundlesCustomValidationConfig,
				},
			},
		},
	}
	workloadKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN2PdPEglb3JjF1Fg
cqyEiRJHqtqzSUBnIeWCixn4hH2hRANCAARW+TsDRr0b0wJqg2kY5JvjX7UfAV3m
MC2hK9d8Z5ENZc9lFW48vObdcHcHdHvAaA8z2GM02pDkTt5pgUvRHlsf
-----END PRIVATE KEY-----
`)
	workloadKey, _ = pemutil.ParseECPrivateKey(workloadKeyPEM)

	workloadCert1           = &x509.Certificate{Raw: []byte("WORKLOAD1")}
	workloadTLSCertificate1 = &tls_v3.Secret{
		Name: "spiffe://domain.test/workload",
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nV09SS0xPQUQx\n-----END CERTIFICATE-----\n"),
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: workloadKeyPEM,
					},
				},
			},
		},
	}

	workloadCert2           = &x509.Certificate{Raw: []byte("WORKLOAD2")}
	workloadTLSCertificate2 = &tls_v3.Secret{
		Name: "spiffe://domain.test/workload",
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nV09SS0xPQUQy\n-----END CERTIFICATE-----\n"),
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: workloadKeyPEM,
					},
				},
			},
		},
	}

	workloadTLSCertificate3 = &tls_v3.Secret{
		Name: "default",
		Type: &tls_v3.Secret_TlsCertificate{
			TlsCertificate: &tls_v3.TlsCertificate{
				CertificateChain: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: []byte("-----BEGIN CERTIFICATE-----\nV09SS0xPQUQx\n-----END CERTIFICATE-----\n"),
					},
				},
				PrivateKey: &core_v3.DataSource{
					Specifier: &core_v3.DataSource_InlineBytes{
						InlineBytes: workloadKeyPEM,
					},
				},
			},
		},
	}

	workloadSelectors = cache.Selectors{{Type: "TYPE", Value: "VALUE"}}

	userAgentVersionTypeV17 = &core_v3.Node_UserAgentBuildVersion{
		UserAgentBuildVersion: &core_v3.BuildVersion{
			Version: &envoy_type_v3.SemanticVersion{
				MajorNumber: 1,
				MinorNumber: 17,
			},
		},
	}

	userAgentVersionTypeV18 = &core_v3.Node_UserAgentBuildVersion{
		UserAgentBuildVersion: &core_v3.BuildVersion{
			Version: &envoy_type_v3.SemanticVersion{
				MajorNumber: 1,
				MinorNumber: 18,
			},
		},
	}
)

func TestStreamSecrets(t *testing.T) {
	for _, tt := range []struct {
		name          string
		req           *discovery_v3.DiscoveryRequest
		config        Config
		expectSecrets []*tls_v3.Secret
		expectCode    codes.Code
		expectMsg     string
	}{
		{
			name: "All Secrets: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{
				tdValidationContext,
				fedValidationContext,
				workloadTLSCertificate1,
			},
		},
		{
			name: "All Secrets: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{
				tdValidationContextSpiffeValidator,
				fedValidationContextSpiffeValidator,
				workloadTLSCertificate1,
			},
		},
		{
			name: "TrustDomain bundle: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "TrustDomain bundle: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Default TrustDomain bundle: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node:          &core_v3.Node{},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Default TrustDomain bundle: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ROOTCA"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext2SpiffeValidator},
		},
		{
			name: "Federated TrustDomain bundle: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://otherdomain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{fedValidationContext},
		},
		{
			name: "Federated TrustDomain bundle: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://otherdomain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{fedValidationContextSpiffeValidator},
		},
		{
			name: "TLS certificates only: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test/workload"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{workloadTLSCertificate1},
		},
		{
			name: "TLS certificates only: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test/workload"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{workloadTLSCertificate1},
		},
		{
			name: "Default All bundles: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ALL"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  `unable to use "SPIFFE validator" on Envoy below 1.17`,
		},
		{
			name: "Default All bundles: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ALL"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{allBundlesValidationContext},
		},
		{
			name: "Default TLS certificate",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"default"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{workloadTLSCertificate3},
		},
		{
			name: "Unknown resource",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test/WHATEVER"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `workload is not authorized for the requested identities ["spiffe://domain.test/WHATEVER"]`,
		},
		{
			name: "Disable custom validation",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable custom validation and set default bundle name to ALL",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"default"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			config: Config{
				DefaultBundleName:           "ALL",
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{workloadTLSCertificate3},
		},
		{
			name: "Disable custom validation and set default bundle name to ALL",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ALL"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			config: Config{
				DefaultBundleName:           "ALL",
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext3},
		},
		{
			name: "Disable custom validation per instance",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewBoolValue(true),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation per instance with string value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("true"),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation set to false per instance",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewBoolValue(false),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation set unknown string value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("test"),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation in config and in envoy node metadata",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("true"),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation in config but opt-in in envoy node metadata with string value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("false"),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation in config but opt-in in envoy node metadata with bool value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewBoolValue(false),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation in config and set to unknown string value in envoy node metadata",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("test"),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation in config and set to unexpected type in envoy node metadata",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewNumberValue(5),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTestWithConfig(t, tt.config)
			defer test.cleanup()

			stream, err := test.handler.StreamSecrets(context.Background())
			require.NoError(t, err)
			defer func() {
				require.NoError(t, stream.CloseSend())
			}()

			test.sendAndWait(stream, tt.req)

			resp, err := stream.Recv()
			spiretest.AssertGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				require.Nil(t, resp)
				return
			}

			requireSecrets(t, resp, tt.expectSecrets...)
		})
	}
}

func TestStreamSecretsStreaming(t *testing.T) {
	test := setupTest(t)
	defer test.server.Stop()

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.NotEmpty(t, resp.VersionInfo)
	require.NotEmpty(t, resp.Nonce)
	requireSecrets(t, resp, workloadTLSCertificate1)

	test.setWorkloadUpdate(workloadCert2)

	resp, err = stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate2)
}

func TestStreamSecretsStreamingKeepNodeInformation(t *testing.T) {
	test := setupTest(t)
	defer test.server.Stop()

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.NotEmpty(t, resp.VersionInfo)
	require.NotEmpty(t, resp.Nonce)
	requireSecrets(t, resp, workloadTLSCertificate1)

	// Update request
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		ResponseNonce: resp.Nonce,
	})
	test.setWorkloadUpdate(workloadCert2)

	resp, err = stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate2)
}

func TestStreamSecretsApplicationDoesNotSpin(t *testing.T) {
	test := setupTest(t)
	defer test.server.Stop()

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	// Subscribe to some updates
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})

	resp, err := stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate1)

	// Reject the update
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   "OHNO",
		ErrorDetail:   &status.Status{Message: "OHNO!"},
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})

	test.setWorkloadUpdate(workloadCert2)

	resp, err = stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate2)
}

func TestStreamSecretsRequestReceivedBeforeWorkloadUpdate(t *testing.T) {
	test := setupTest(t)
	defer test.server.Stop()

	test.setWorkloadUpdate(nil)

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})

	test.setWorkloadUpdate(workloadCert2)

	resp, err := stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate2)
}

func TestStreamSecretsSubChanged(t *testing.T) {
	test := setupTest(t)
	defer test.server.Stop()

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})

	resp, err := stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate1)

	// Ack the response
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test/workload"},
	})

	// Send another request for different resources.
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})

	resp, err = stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, tdValidationContext)
}

func TestStreamSecretsBadNonce(t *testing.T) {
	test := setupTest(t)
	defer test.server.Stop()

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	// The first request should be good
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})
	resp, err := stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate1)

	// Now update the workload SVID
	test.setWorkloadUpdate(workloadCert2)

	// The third request should be ignored because the nonce isn't set to
	// the value returned in the response.
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: "FOO",
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})

	// The fourth request should be good since the nonce matches that sent with
	// the last response.
	test.sendAndWait(stream, &discovery_v3.DiscoveryRequest{
		ResponseNonce: resp.Nonce,
		VersionInfo:   resp.VersionInfo,
		ResourceNames: []string{"spiffe://domain.test/workload"},
		Node: &core_v3.Node{
			UserAgentVersionType: userAgentVersionTypeV17,
		},
	})
	resp, err = stream.Recv()
	require.NoError(t, err)
	requireSecrets(t, resp, workloadTLSCertificate2)
}

func TestStreamSecretsErrInSubscribeToCacheChanges(t *testing.T) {
	test := setupErrTest(t)
	defer test.server.Stop()

	stream, err := test.handler.StreamSecrets(context.Background())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, stream.CloseSend())
	}()

	resp, err := stream.Recv()
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestFetchSecrets(t *testing.T) {
	for _, tt := range []struct {
		name          string
		req           *discovery_v3.DiscoveryRequest
		config        Config
		expectSecrets []*tls_v3.Secret
		expectCode    codes.Code
		expectMsg     string
	}{
		{
			name: "Fetch all secrets: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				TypeUrl: "TYPEURL",
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{
				tdValidationContext,
				fedValidationContext,
				workloadTLSCertificate1,
			},
		},
		{
			name: "Fetch all secrets: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				TypeUrl: "TYPEURL",
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{
				tdValidationContextSpiffeValidator,
				fedValidationContextSpiffeValidator,
				workloadTLSCertificate1,
			},
		},
		{
			name: "TrustDomain bundle: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "TrustDomain bundle: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Federated bundle: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://otherdomain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{fedValidationContext},
		},
		{
			name: "Federated bundle: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://otherdomain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{fedValidationContextSpiffeValidator},
		},
		{
			name: "Default All bundles: RootCA",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ALL"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  `unable to use "SPIFFE validator" on Envoy below 1.17`,
		},
		{
			name: "Default all bundles: SPIFFE",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ALL"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			expectSecrets: []*tls_v3.Secret{allBundlesValidationContext},
		},
		{
			name: "TLS Certificate",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test/workload"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectSecrets: []*tls_v3.Secret{workloadTLSCertificate1},
		},
		{
			name: "Non-existent resource",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test/other"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV17,
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `workload is not authorized for the requested identities ["spiffe://domain.test/other"]`,
		},
		{
			name: "Disable custom validation",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable custom validation and set default bundle name to ALL",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"default"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			config: Config{
				DefaultBundleName:           "ALL",
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{workloadTLSCertificate3},
		},
		{
			name: "Disable custom validation and set default bundle name to ALL",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"ALL"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
				},
			},
			config: Config{
				DefaultBundleName:           "ALL",
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext3},
		},
		{
			name: "Disable custom validation per instance",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewBoolValue(true),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation per instance with string value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("true"),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation set to false per instance",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewBoolValue(false),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation set unknown string value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("test"),
						},
					},
				},
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation in config and in envoy node metadata",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("true"),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation in config but opt-in in envoy node metadata with string value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("false"),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation in config but opt-in in envoy node metadata with bool value",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewBoolValue(false),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContextSpiffeValidator},
		},
		{
			name: "Disable SPIFFE cert validation in config and set to unknown string value in envoy node metadata",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewStringValue("test"),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
		{
			name: "Disable SPIFFE cert validation in config and set to unexpected type in envoy node metadata",
			req: &discovery_v3.DiscoveryRequest{
				ResourceNames: []string{"spiffe://domain.test"},
				Node: &core_v3.Node{
					UserAgentVersionType: userAgentVersionTypeV18,
					Metadata: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							disableSPIFFECertValidationKey: structpb.NewNumberValue(100500),
						},
					},
				},
			},
			config: Config{
				DisableSPIFFECertValidation: true,
			},
			expectSecrets: []*tls_v3.Secret{tdValidationContext},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupTestWithConfig(t, tt.config)
			defer test.server.Stop()

			resp, err := test.handler.FetchSecrets(context.Background(), tt.req)

			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			if tt.expectCode != codes.OK {
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Empty(t, resp.VersionInfo)
			require.Empty(t, resp.Nonce)
			require.Equal(t, tt.req.TypeUrl, resp.TypeUrl)
			requireSecrets(t, resp, tt.expectSecrets...)
		})
	}
}

func setupTest(t *testing.T) *handlerTest {
	return setupTestWithManager(t, Config{}, NewFakeManager(t))
}

func setupErrTest(t *testing.T) *handlerTest {
	manager := NewFakeManager(t)
	manager.err = errors.New("bad-error")
	return setupTestWithManager(t, Config{}, manager)
}

func setupTestWithManager(t *testing.T, c Config, manager *FakeManager) *handlerTest {
	defaultConfig := Config{
		Manager:                     manager,
		Attestor:                    FakeAttestor(workloadSelectors),
		DefaultSVIDName:             "default",
		DefaultBundleName:           "ROOTCA",
		DefaultAllBundlesName:       "ALL",
		DisableSPIFFECertValidation: false,
	}
	require.NoError(t, mergo.Merge(&c, defaultConfig))
	handler := New(c)

	received := make(chan struct{})
	handler.hooks.received = received

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	log, _ := test.NewNullLogger()
	unaryInterceptor, streamInterceptor := middleware.Interceptors(middleware.WithLogger(log))
	server := grpc.NewServer(grpc.Creds(FakeCreds{}),
		grpc.UnaryInterceptor(unaryInterceptor),
		grpc.StreamInterceptor(streamInterceptor),
	)
	secret_v3.RegisterSecretDiscoveryServiceServer(server, handler)
	go func() { _ = server.Serve(listener) }()

	test := &handlerTest{
		t:        t,
		manager:  manager,
		server:   server,
		handler:  secret_v3.NewSecretDiscoveryServiceClient(conn),
		received: received,
	}

	test.setWorkloadUpdate(workloadCert1)

	return test
}

func setupTestWithConfig(t *testing.T, c Config) *handlerTest {
	manager := NewFakeManager(t)
	return setupTestWithManager(t, c, manager)
}

type handlerTest struct {
	t *testing.T

	manager  *FakeManager
	server   *grpc.Server
	handler  secret_v3.SecretDiscoveryServiceClient
	received chan struct{}
}

func (h *handlerTest) cleanup() {
	h.server.Stop()
}

func (h *handlerTest) setWorkloadUpdate(workloadCert *x509.Certificate) {
	var workloadUpdate *cache.WorkloadUpdate
	if workloadCert != nil {
		workloadUpdate = &cache.WorkloadUpdate{
			Identities: []cache.Identity{
				{
					Entry: &common.RegistrationEntry{
						SpiffeId: "spiffe://domain.test/workload",
					},
					SVID:       []*x509.Certificate{workloadCert},
					PrivateKey: workloadKey,
				},
			},
			Bundle: tdBundle,
			FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
				spiffeid.RequireTrustDomainFromString("otherdomain.test"): fedBundle,
			},
		}
	}
	h.manager.SetWorkloadUpdate(workloadUpdate)
}

func (h *handlerTest) sendAndWait(stream secret_v3.SecretDiscoveryService_StreamSecretsClient, req *discovery_v3.DiscoveryRequest) {
	require.NoError(h.t, stream.Send(req))
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-h.received:
	case <-timer.C:
		assert.Fail(h.t, "timed out waiting for request to be received")
	}
}

type FakeAttestor []*common.Selector

func (a FakeAttestor) Attest(context.Context) ([]*common.Selector, error) {
	return ([]*common.Selector)(a), nil
}

type FakeManager struct {
	t *testing.T

	mu   sync.Mutex
	upd  *cache.WorkloadUpdate
	next int
	subs map[int]chan *cache.WorkloadUpdate
	err  error
}

func NewFakeManager(t *testing.T) *FakeManager {
	return &FakeManager{
		t:    t,
		subs: make(map[int]chan *cache.WorkloadUpdate),
	}
}

func (m *FakeManager) SubscribeToCacheChanges(_ context.Context, selectors cache.Selectors) (cache.Subscriber, error) {
	if m.err != nil {
		return nil, m.err
	}
	require.Equal(m.t, workloadSelectors, selectors)

	updch := make(chan *cache.WorkloadUpdate, 1)
	if m.upd != nil {
		updch <- m.upd
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.next
	m.next++
	m.subs[key] = updch
	return NewFakeSubscriber(updch, func() {
		delete(m.subs, key)
		close(updch)
	}), nil
}

func (m *FakeManager) FetchWorkloadUpdate([]*common.Selector) *cache.WorkloadUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upd
}

func (m *FakeManager) SetWorkloadUpdate(upd *cache.WorkloadUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.upd = upd
	for _, sub := range m.subs {
		select {
		case sub <- upd:
		default:
			<-sub
			sub <- upd
		}
	}
}

type FakeSubscriber struct {
	updch <-chan *cache.WorkloadUpdate
	done  func()
}

func NewFakeSubscriber(updch <-chan *cache.WorkloadUpdate, done func()) *FakeSubscriber {
	return &FakeSubscriber{
		updch: updch,
		done:  done,
	}
}

func (s *FakeSubscriber) Updates() <-chan *cache.WorkloadUpdate {
	return s.updch
}

func (s *FakeSubscriber) Finish() {
	s.done()
}

type FakeCreds struct{}

func (c FakeCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("unexpected")
}

func (c FakeCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, peertracker.AuthInfo{Watcher: FakeWatcher{}}, nil
}

func (c FakeCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "fixed",
		SecurityVersion:  "0.1",
		ServerName:       "sds-handler-test",
	}
}

func (c FakeCreds) Clone() credentials.TransportCredentials {
	return &c
}

func (c FakeCreds) OverrideServerName(_ string) error {
	return nil
}

type FakeWatcher struct{}

func (w FakeWatcher) Close() {}

func (w FakeWatcher) IsAlive() error { return nil }

func (w FakeWatcher) PID() int32 { return 123 }

func requireSecrets(t *testing.T, resp *discovery_v3.DiscoveryResponse, expectedSecrets ...*tls_v3.Secret) {
	var actualSecrets []*tls_v3.Secret
	for _, resource := range resp.Resources {
		secret := new(tls_v3.Secret)
		require.NoError(t, resource.UnmarshalTo(secret)) //nolint: scopelint // pointer to resource isn't held
		actualSecrets = append(actualSecrets, secret)
	}

	spiretest.RequireProtoListEqual(t, expectedSecrets, actualSecrets)
}
