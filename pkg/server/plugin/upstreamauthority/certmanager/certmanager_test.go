package certmanager

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	cmapi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager/internal/v1"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake" //nolint:staticcheck
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
		issuerGroup = "exmaple.cert-manager.io"
		namespace   = "spire"
	)

	csr, _, err := util.NewCSRTemplate(trustDomain.IDString())
	require.NoError(t, err)

	root, rootPEM := testingCAPEM(t)
	intermediate, intermediatePEM := testingCAPEM(t)

	tests := map[string]struct {
		request              *upstreamauthorityv0.MintX509CARequest
		updateCR             func(t *testing.T, cr *cmapi.CertificateRequest)
		expX509CaChain       [][]byte
		expUpstreamX509Roots [][]byte
		expError             bool
	}{
		"a request that results in being denied should be deleted and an error returned": {
			request: &upstreamauthorityv0.MintX509CARequest{
				Csr:          csr,
				PreferredTtl: 360000,
			},
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionDenied, Status: cmapi.ConditionTrue})
			},
			expX509CaChain:       nil,
			expUpstreamX509Roots: nil,
			expError:             true,
		},
		"a request that results in failed should be deleted and an error returned": {
			request: &upstreamauthorityv0.MintX509CARequest{
				Csr:          csr,
				PreferredTtl: 360000,
			},
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionFalse, Reason: cmapi.CertificateRequestReasonFailed})
			},
			expX509CaChain:       nil,
			expUpstreamX509Roots: nil,
			expError:             true,
		},
		"a request that is signed, but returns a invalid intermediate certificate should be deleted and error returned": {
			request: &upstreamauthorityv0.MintX509CARequest{
				Csr:          csr,
				PreferredTtl: 360000,
			},
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = []byte("bad certificate")
				cr.Status.CA = rootPEM
			},
			expX509CaChain:       nil,
			expUpstreamX509Roots: nil,
			expError:             true,
		},
		"a request that is signed, but returns a invalid root certificate should be deleted and error returned": {
			request: &upstreamauthorityv0.MintX509CARequest{
				Csr:          csr,
				PreferredTtl: 360000,
			},
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = intermediatePEM
				cr.Status.CA = []byte("bad certificate")
			},
			expX509CaChain:       nil,
			expUpstreamX509Roots: nil,
			expError:             true,
		},
		"a request that is signed, but does not set a CA should be deleted and an error returned": {
			request: &upstreamauthorityv0.MintX509CARequest{
				Csr:          csr,
				PreferredTtl: 360000,
			},
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = intermediatePEM
			},
			expX509CaChain:       nil,
			expUpstreamX509Roots: nil,
			expError:             true,
		},
		"a request that is signed should be deleted and return the intermediate and root certificate": {
			request: &upstreamauthorityv0.MintX509CARequest{
				Csr:          csr,
				PreferredTtl: 360000,
			},
			updateCR: func(t *testing.T, cr *cmapi.CertificateRequest) {
				cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmapi.ConditionTrue})
				cr.Status.Certificate = intermediatePEM
				cr.Status.CA = rootPEM
			},
			expX509CaChain:       [][]byte{intermediate.Raw},
			expUpstreamX509Roots: [][]byte{root.Raw},
			expError:             false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cmclient := fakeclient.NewFakeClientWithScheme(scheme)
			logOptions := hclog.DefaultOptions
			logOptions.Level = hclog.Debug

			crCreated := make(chan struct{}, 1)
			staleCRsDeleted := make(chan struct{}, 1)
			p := &Plugin{
				log:         hclog.New(logOptions),
				cmclient:    cmclient,
				trustDomain: trustDomain.String(),
				config: &Config{
					IssuerName:  issuerName,
					IssuerKind:  issuerKind,
					IssuerGroup: issuerGroup,
					Namespace:   namespace,
				},
				hooks: hooks{
					onCreateCR: func() {
						crCreated <- struct{}{}
					},
					onCleanupStaleCRs: func() {
						staleCRsDeleted <- struct{}{}
					},
				},
			}

			registerFn := func(s *grpc.Server) {
				upstreamauthorityv0.RegisterUpstreamAuthorityServer(s, p)
			}
			contextFn := func(ctx context.Context) context.Context {
				return ctx
			}

			// Set create client and add to test
			conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
			defer done()

			pluginClient := upstreamauthorityv0.NewUpstreamAuthorityClient(conn)
			r, err := pluginClient.MintX509CA(context.TODO(), test.request)
			require.NoError(t, err)

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

			resp, err := r.Recv()
			require.Equal(t, test.expError, err != nil, "unexpected error", err)

			if resp != nil {
				require.Equal(t, test.expX509CaChain, resp.X509CaChain, "unexpected X509CaChain")
				require.Equal(t, test.expUpstreamX509Roots, resp.UpstreamX509Roots, "unexpected UpstreamX509Roots")
			}

			// ensure that CertificateRequests are cleaned up
			<-staleCRsDeleted
			crList := &cmapi.CertificateRequestList{}
			require.NoError(t, cmclient.List(context.TODO(), crList))
			require.Len(t, crList.Items, 0, "expected no CertificateRequests to remain")
		})
	}
}

func Test_loadConfig(t *testing.T) {
	tests := map[string]struct {
		inpConfig string
		expErr    bool
		expConfig *Config
	}{
		"if config is malformed, expect error": {
			inpConfig: `
         issuer_name_foo = "my-issuer"
			`,
			expErr:    true,
			expConfig: nil,
		},
		"if config is missing an issuer_name, expect error": {
			inpConfig: `
				 issuer_kind = "my-kind"
				 issuer_group = "my-group"
				 namespace = "my-namespace"
				 kube_config_file = "/path/to/config"
			`,
			expErr:    true,
			expConfig: nil,
		},
		"if config is missing a namespace, expect error": {
			inpConfig: `
         issuer_name = "my-issuer"
				 issuer_kind = "my-kind"
				 issuer_group = "my-group"
				 kube_config_file = "/path/to/config"
			`,
			expErr:    true,
			expConfig: nil,
		},
		"if config is fully populated, return config": {
			inpConfig: `
         issuer_name = "my-issuer"
				 issuer_kind = "my-kind"
				 issuer_group = "my-group"
				 namespace = "my-namespace"
				 kube_config_file = "/path/to/config"
			`,
			expErr: false,
			expConfig: &Config{
				IssuerName:         "my-issuer",
				IssuerKind:         "my-kind",
				IssuerGroup:        "my-group",
				Namespace:          "my-namespace",
				KubeConfigFilePath: "/path/to/config",
			},
		},
		"if config is partly populated, expect defaulting": {
			inpConfig: `
         issuer_name = "my-issuer"
				 namespace = "my-namespace"
				 kube_config_file = "/path/to/config"
			`,
			expErr: false,
			expConfig: &Config{
				IssuerName:         "my-issuer",
				IssuerKind:         "Issuer",
				IssuerGroup:        "cert-manager.io",
				Namespace:          "my-namespace",
				KubeConfigFilePath: "/path/to/config",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			plugin := New()
			plugin.SetLogger(hclog.Default())

			config, err := plugin.loadConfig(&spi.ConfigureRequest{
				Configuration: test.inpConfig,
			})

			require.Equal(t, test.expErr, (err != nil))
			if err != nil {
				require.Equal(t, codes.InvalidArgument, status.Code(err))
			}
			require.Equal(t, test.expConfig, config)
		})
	}
}
