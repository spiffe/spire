package certmanager

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	cmapi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager/internal/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testingCAPEM(t *testing.T) (*x509.Certificate, []byte) {
	ca, _, err := util.LoadCAFixture()
	require.NoError(t, err)
	encodedCA := new(bytes.Buffer)
	err = pem.Encode(encodedCA, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	})
	require.NoError(t, err)
	return ca, encodedCA.Bytes()
}

func Test_MintX509CA(t *testing.T) {
	var (
		trustDomain = spiffeid.RequireTrustDomainFromString("example.com")
		issuerName  = "test-issuer"
		issuerKind  = "Issuer"
		issuerGroup = "example.cert-manager.io"
		namespace   = "spire"
	)

	csr, _, err := util.NewCSRTemplate(trustDomain.IDString())
	require.NoError(t, err)

	root, rootPEM := testingCAPEM(t)
	intermediate, intermediatePEM := testingCAPEM(t)

	tests := map[string]struct {
		csr                   []byte
		preferredTTL          time.Duration
		updateCR              func(t *testing.T, cr *cmapi.CertificateRequest)
		expectX509CA          []*x509.Certificate
		expectX509Authorities []*x509.Certificate
		expectCode            codes.Code
		expectMsgPrefix       string
	}{
		"a request that results in being denied should be deleted and an error returned": {
			csr:          csr,
			preferredTTL: 360000 * time.Second,
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionDenied, Status: cmapi.ConditionTrue})
			},
			expectCode:      codes.PermissionDenied,
			expectMsgPrefix: "request has been denied",
		},
		"a request that results in failed should be deleted and an error returned": {
			csr:          csr,
			preferredTTL: 360000 * time.Second,
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed})
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "request has failed",
		},
		"a request that is signed, but returns a invalid intermediate certificate should be deleted and error returned": {
			csr:          csr,
			preferredTTL: 360000 * time.Second,
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = []byte("bad certificate")
				cr.Status.CA = rootPEM
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(cert-manager): failed to parse certificate: no PEM blocks",
		},
		"a request that is signed, but returns a invalid root certificate should be deleted and error returned": {
			csr:          csr,
			preferredTTL: 360000 * time.Second,
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = intermediatePEM
				cr.Status.CA = []byte("bad certificate")
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(cert-manager): failed to parse CA certificate: no PEM blocks",
		},
		"a request that is signed, but does not set a CA should be deleted and an error returned": {
			csr:          csr,
			preferredTTL: 360000 * time.Second,
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = intermediatePEM
			},
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(cert-manager): no upstream CA root returned from request",
		},
		"a request that is signed should be deleted and return the intermediate and root certificate": {
			csr:          csr,
			preferredTTL: 360000 * time.Second,
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = intermediatePEM
				cr.Status.CA = rootPEM
			},
			expectX509CA:          []*x509.Certificate{intermediate},
			expectX509Authorities: []*x509.Certificate{root},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cmclient := fakeclient.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&cmapi.CertificateRequest{}).Build()
			crCreated := make(chan struct{}, 1)
			staleCRsDeleted := make(chan struct{}, 1)

			p := &Plugin{
				hooks: hooks{
					newClient: func(configPath string) (client.Client, error) {
						return cmclient, nil
					},
					onCreateCR: func() {
						crCreated <- struct{}{}
					},
					onCleanupStaleCRs: func() {
						staleCRsDeleted <- struct{}{}
					},
				},
			}
			config := &Config{
				IssuerName:  issuerName,
				IssuerKind:  issuerKind,
				IssuerGroup: issuerGroup,
				Namespace:   namespace,
			}
			ua := new(upstreamauthority.V1)
			plugintest.Load(t, builtin(p), ua,
				plugintest.ConfigureJSON(config),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: trustDomain,
				}),
			)

			go func() {
				<-crCreated
				crList := &cmapi.CertificateRequestList{}
				assert.NoError(t, cmclient.List(context.TODO(), crList))
				cr := &crList.Items[0]

				assert.Equal(t, namespace, cr.Namespace)
				assert.Equal(t, time.Hour*100, cr.Spec.Duration.Duration)
				assert.Equal(t, issuerName, cr.Spec.IssuerRef.Name)
				assert.Equal(t, issuerKind, cr.Spec.IssuerRef.Kind)
				assert.Equal(t, issuerGroup, cr.Spec.IssuerRef.Group)

				test.updateCR(t, cr)
				assert.NoError(t, cmclient.Status().Update(context.TODO(), cr))
			}()

			x509CA, x509Authorities, stream, err := ua.MintX509CA(context.Background(), csr, test.preferredTTL)
			spiretest.RequireGRPCStatusContains(t, err, test.expectCode, test.expectMsgPrefix)

			if test.expectCode != codes.OK {
				assert.Nil(t, x509CA)
				assert.Nil(t, x509Authorities)
				assert.Nil(t, stream)
			} else {
				require.NotNil(t, stream)
				require.Equal(t, test.expectX509CA, x509CA, "unexpected X509CaChain")

				require.Equal(t, test.expectX509Authorities, x509Authorities, "unexpected UpstreamX509Roots")

				// Plugin does not support streaming back changes so assert the
				// stream returns EOF.
				_, streamErr := stream.RecvUpstreamX509Authorities()
				assert.True(t, errors.Is(streamErr, io.EOF))
			}

			// ensure that CertificateRequests are cleaned up
			<-staleCRsDeleted
			crList := &cmapi.CertificateRequestList{}
			require.NoError(t, cmclient.List(context.TODO(), crList))
			require.Len(t, crList.Items, 0, "expected no CertificateRequests to remain")
		})
	}
}

func Test_Configure(t *testing.T) {
	tests := map[string]struct {
		inpConfig          string
		expectCode         codes.Code
		expectMsgPrefix    string
		expectConfig       *Config
		expectConfigFile   string
		overrideCoreConfig *catalog.CoreConfig
		newClientErr       error
	}{
		"if config is malformed, expect error": {
			inpConfig:       "MALFORMED",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "failed to decode configuration file:",
		},
		"if config is missing an issuer_name, expect error": {
			inpConfig: `
		issuer_kind = "my-kind"
		issuer_group = "my-group"
		namespace = "my-namespace"
		kube_config_file = "/path/to/config"
		`,
			expectConfig:    nil,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "configuration has empty issuer_name property",
		},
		"if config is missing a namespace, expect error": {
			inpConfig: `
		issuer_name = "my-issuer"
		issuer_kind = "my-kind"
		issuer_group = "my-group"
		kube_config_file = "/path/to/config"
		`,
			expectConfig:    nil,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "configuration has empty namespace property",
		},
		"if config is fully populated, return config": {
			inpConfig: `
		issuer_name = "my-issuer"
		issuer_kind = "my-kind"
		issuer_group = "my-group"
		namespace = "my-namespace"
		kube_config_file = "/path/to/config"
		`,
			expectConfig: &Config{
				IssuerName:         "my-issuer",
				IssuerKind:         "my-kind",
				IssuerGroup:        "my-group",
				Namespace:          "my-namespace",
				KubeConfigFilePath: "/path/to/config",
			},
			expectConfigFile: "/path/to/config",
		},
		"if config is partly populated, expect defaulting": {
			inpConfig: `
		issuer_name = "my-issuer"
		namespace = "my-namespace"
		kube_config_file = "/path/to/config"
		`,
			expectConfig: &Config{
				IssuerName:         "my-issuer",
				IssuerKind:         "Issuer",
				IssuerGroup:        "cert-manager.io",
				Namespace:          "my-namespace",
				KubeConfigFilePath: "/path/to/config",
			},
			expectConfigFile: "/path/to/config",
		},
		"no trust domain": {
			inpConfig: `
		issuer_name = "my-issuer"
		namespace = "my-namespace"
		kube_config_file = "/path/to/config"
		`,
			overrideCoreConfig: &catalog.CoreConfig{},
			expectCode:         codes.InvalidArgument,
			expectMsgPrefix:    "trust_domain is required",
		},
		"failed to create client": {
			inpConfig: `
		issuer_name = "my-issuer"
		namespace = "my-namespace"
		kube_config_file = "/path/to/config"
		`,
			newClientErr:     errors.New("some error"),
			expectCode:       codes.Internal,
			expectMsgPrefix:  "failed to create cert-manager client: some error",
			expectConfigFile: "/path/to/config",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var err error

			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.Configure(test.inpConfig),
			}

			if test.overrideCoreConfig != nil {
				options = append(options, plugintest.CoreConfig(*test.overrideCoreConfig))
			} else {
				options = append(options, plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("localhost"),
				}))
			}

			p := &Plugin{
				hooks: hooks{
					newClient: func(configPath string) (client.Client, error) {
						assert.Equal(t, test.expectConfigFile, configPath)
						if test.newClientErr != nil {
							return nil, test.newClientErr
						}
						return fakeclient.NewClientBuilder().WithScheme(scheme).Build(), nil
					},
				},
			}

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, test.expectCode, test.expectMsgPrefix)
			if test.expectCode != codes.OK {
				require.Nil(t, p.config)
				require.Nil(t, p.cmclient)
				return
			}

			require.Equal(t, test.expectConfig, p.config)
			require.NotNil(t, p.cmclient)
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	cmclient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	p := &Plugin{
		hooks: hooks{
			newClient: func(configPath string) (client.Client, error) {
				return cmclient, nil
			},
		},
	}
	config := &Config{
		IssuerName:  "test-issuer",
		IssuerKind:  "Issuer",
		IssuerGroup: "example.cert-manager.io",
		Namespace:   "spire",
	}
	ua := new(upstreamauthority.V1)
	plugintest.Load(t, builtin(p), ua,
		plugintest.ConfigureJSON(config),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.com"),
		}),
	)

	pkixBytes, err := x509.MarshalPKIXPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)

	jwtAuthorities, stream, err := ua.PublishJWTKey(context.Background(), &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority(cert-manager): publishing upstream is unsupported")
	assert.Nil(t, jwtAuthorities)
	assert.Nil(t, stream)
}
