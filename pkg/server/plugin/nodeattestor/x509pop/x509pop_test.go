package x509pop

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestX509PoP(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	rootCertPath     string
	leafBundle       [][]byte
	leafKey          crypto.PrivateKey
	leafCert         *x509.Certificate
	intermediateCert *x509.Certificate
	rootCert         *x509.Certificate
	svidReg          [][]byte
	svidExchange     [][]byte

	alternativeBundlePath string
	alternativeBundle     *x509.Certificate
}

func (s *Suite) SetupTest() {
	require := s.Require()

	s.rootCertPath = fixture.Join("nodeattestor", "x509pop", "root-crt.pem")
	leafCertPath := fixture.Join("nodeattestor", "x509pop", "leaf-crt-bundle.pem")
	leafKeyPath := fixture.Join("nodeattestor", "x509pop", "leaf-key.pem")
	svidRegPath := fixture.Join("nodeattestor", "x509pop", "svidreg.pem")
	svidExchangePath := fixture.Join("nodeattestor", "x509pop", "svidexchange.pem")

	kp, err := tls.LoadX509KeyPair(leafCertPath, leafKeyPath)
	require.NoError(err)
	s.leafBundle = kp.Certificate
	s.leafKey = kp.PrivateKey
	s.leafCert, err = x509.ParseCertificate(s.leafBundle[0])
	require.NoError(err)
	s.intermediateCert, err = x509.ParseCertificate(s.leafBundle[1])
	require.NoError(err)
	s.rootCert, err = util.LoadCert(s.rootCertPath)
	require.NoError(err)

	kp, err = tls.LoadX509KeyPair(svidRegPath, leafKeyPath)
	require.NoError(err)
	s.svidReg = kp.Certificate
	require.NoError(err)

	kp, err = tls.LoadX509KeyPair(svidExchangePath, leafKeyPath)
	require.NoError(err)
	s.svidExchange = kp.Certificate

	// Add alternative bundle
	s.alternativeBundlePath = fixture.Join("certs", "ca.pem")
	s.alternativeBundle, err = util.LoadCert(s.alternativeBundlePath)
	require.NoError(err)
}

func (s *Suite) TestAttestSuccess() {
	tests := []struct {
		desc          string
		giveConfig    string
		expectAgentID string
		certs         [][]byte
		serialnumber  string
	}{
		{
			desc:          "default success (ca_bundle_path)",
			expectAgentID: "spiffe://example.org/spire/agent/x509pop/" + x509pop.Fingerprint(s.leafCert),
			giveConfig:    s.createConfiguration("ca_bundle_path", ""),
			certs:         s.leafBundle,
			serialnumber:  "serialnumber:0a1b2c3d4e5f",
		},
		{
			desc:          "success with custom agent id (ca_bundle_path)",
			expectAgentID: "spiffe://example.org/spire/agent/cn/COMMONNAME",
			giveConfig:    s.createConfiguration("ca_bundle_path", `agent_path_template = "/cn/{{ .Subject.CommonName }}"`),
			certs:         s.leafBundle,
			serialnumber:  "serialnumber:0a1b2c3d4e5f",
		},
		{
			desc:          "default success (ca_bundle_paths)",
			expectAgentID: "spiffe://example.org/spire/agent/x509pop/" + x509pop.Fingerprint(s.leafCert),
			giveConfig:    s.createConfiguration("ca_bundle_path", ""),
			certs:         s.leafBundle,
			serialnumber:  "serialnumber:0a1b2c3d4e5f",
		},
		{
			desc:          "success with custom agent id (ca_bundle_paths)",
			expectAgentID: "spiffe://example.org/spire/agent/serialnumber/0a1b2c3d4e5f",
			giveConfig:    s.createConfiguration("ca_bundle_paths", `agent_path_template = "/serialnumber/{{ .SerialNumberHex }}"`),
			certs:         s.leafBundle,
			serialnumber:  "serialnumber:0a1b2c3d4e5f",
		},
		{
			desc:          "success with spiffe exchange",
			expectAgentID: "spiffe://example.org/spire/agent/x509pop/testhost",
			giveConfig:    s.createConfigurationModeSPIFFE(""),
			certs:         s.svidExchange,
			serialnumber:  "serialnumber:0a1b2c3d4e7f",
		},
	}

	for _, tt := range tests {
		tt := tt // alias loop variable as it is used in the closure
		s.T().Run(tt.desc, func(t *testing.T) {
			attestor := s.loadPlugin(t, tt.giveConfig)

			attestationData := &x509pop.AttestationData{
				Certificates: tt.certs,
			}
			payload := marshal(t, attestationData)

			challengeFn := func(ctx context.Context, challenge []byte) ([]byte, error) {
				require.NotEmpty(t, challenge)
				popChallenge := new(x509pop.Challenge)
				unmarshal(t, challenge, popChallenge)

				// calculate and send the response
				response, err := x509pop.CalculateResponse(s.leafKey, popChallenge)
				require.NoError(t, err)
				return marshal(t, response), nil
			}

			result, err := attestor.Attest(context.Background(), payload, challengeFn)

			require.NoError(t, err)
			require.Equal(t, tt.expectAgentID, result.AgentID)

			spiretest.AssertProtoListEqual(t,
				[]*common.Selector{
					{Type: "x509pop", Value: "subject:cn:COMMONNAME"},
					{Type: "x509pop", Value: "ca:fingerprint:" + x509pop.Fingerprint(s.intermediateCert)},
					{Type: "x509pop", Value: "ca:fingerprint:" + x509pop.Fingerprint(s.rootCert)},
					{Type: "x509pop", Value: tt.serialnumber},
				}, result.Selectors)
		})
	}
}

func (s *Suite) TestAttestFailure() {
	successConfiguration := s.createConfiguration("ca_bundle_path", "")
	spiffeConfiguration := s.createConfigurationModeSPIFFE("")

	makePayload := func(t *testing.T, attestationData *x509pop.AttestationData) []byte {
		return marshal(t, attestationData)
	}

	attestFails := func(t *testing.T, attestor nodeattestor.NodeAttestor, payload []byte, expectCode codes.Code, expectMessage string) {
		result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)

		spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMessage)
		require.Nil(t, result)
	}

	challengeResponseFails := func(t *testing.T, attestor nodeattestor.NodeAttestor, certs [][]byte, challengeResp string, fullChallenge bool, expectCode codes.Code, expectMessage string) {
		payload := makePayload(t, &x509pop.AttestationData{
			Certificates: certs,
		})
		doChallenge := func(ctx context.Context, challenge []byte) ([]byte, error) {
			return []byte(challengeResp), nil
		}
		if fullChallenge {
			doChallenge = func(ctx context.Context, challenge []byte) ([]byte, error) {
				require.NotEmpty(t, challenge)
				popChallenge := new(x509pop.Challenge)
				unmarshal(t, challenge, popChallenge)
				response, err := x509pop.CalculateResponse(s.leafKey, popChallenge)
				require.NoError(t, err)
				return marshal(t, response), nil
			}
		}
		result, err := attestor.Attest(context.Background(), payload, doChallenge)
		spiretest.RequireGRPCStatusContains(t, err, expectCode, expectMessage)
		require.Nil(t, result)
	}

	s.T().Run("not configured", func(t *testing.T) {
		attestor := new(nodeattestor.V1)
		plugintest.Load(t, BuiltIn(), attestor,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(fakeidentityprovider.New())),
		)
		attestFails(t, attestor, []byte("payload"), codes.FailedPrecondition,
			"nodeattestor(x509pop): not configured")
	})

	s.T().Run("unexpected data type", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		attestFails(t, attestor, []byte("payload"), codes.InvalidArgument,
			"nodeattestor(x509pop): failed to unmarshal data")
	})

	s.T().Run("no certificate", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		payload := makePayload(t, &x509pop.AttestationData{})

		attestFails(t, attestor, payload, codes.InvalidArgument,
			"nodeattestor(x509pop): no certificate to attest")
	})

	s.T().Run("malformed leaf", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		payload := makePayload(t, &x509pop.AttestationData{Certificates: [][]byte{{0x00}}})

		attestFails(t, attestor, payload, codes.InvalidArgument,
			"nodeattestor(x509pop): unable to parse leaf certificate")
	})

	s.T().Run("malformed intermediate", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		payload := makePayload(t, &x509pop.AttestationData{Certificates: [][]byte{s.leafBundle[0], {0x00}}})

		attestFails(t, attestor, payload, codes.InvalidArgument,
			"nodeattestor(x509pop): unable to parse intermediate certificate 0")
	})

	s.T().Run("incomplete chain of trust", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		payload := makePayload(t, &x509pop.AttestationData{Certificates: s.leafBundle[:1]})

		attestFails(t, attestor, payload, codes.PermissionDenied,
			"nodeattestor(x509pop): certificate verification failed")
	})

	s.T().Run("malformed challenge response", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		challengeResponseFails(t, attestor, s.leafBundle, "", false, codes.InvalidArgument, "nodeattestor(x509pop): unable to unmarshal challenge response")
	})

	s.T().Run("invalid response", func(t *testing.T) {
		attestor := s.loadPlugin(t, successConfiguration)
		challengeResponseFails(t, attestor, s.leafBundle, "{}", false, codes.PermissionDenied, "nodeattestor(x509pop): challenge response verification failed")
	})

	s.T().Run("spiffe bad prefix", func(t *testing.T) {
		attestor := s.loadPlugin(t, spiffeConfiguration)

		challengeResponseFails(t, attestor, s.svidReg, "", true, codes.PermissionDenied, "nodeattestor(x509pop): x509 cert doesnt match SVID prefix")
	})

	s.T().Run("spiffe non svid", func(t *testing.T) {
		attestor := s.loadPlugin(t, spiffeConfiguration)

		challengeResponseFails(t, attestor, s.leafBundle, "", true, codes.PermissionDenied, "nodeattestor(x509pop): valid SVID x509 cert not found")
	})

	s.T().Run("spiffe non svid", func(t *testing.T) {
		attestor := s.loadPluginFull(t, spiffeConfiguration, fakeidentityprovider.New())

		challengeResponseFails(t, attestor, s.svidExchange, "", true, codes.Internal, "nodeattestor(x509pop): failed to get trust bundle")
	})
}

func (s *Suite) TestConfigure() {
	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(t, BuiltIn(), nil,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(fakeidentityprovider.New())),
			plugintest.CaptureConfigureError(&err),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed", func(t *testing.T) {
		err := doConfig(t, coreConfig, `bad juju`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
	})

	s.T().Run("missing trust_domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, `
		ca_bundle_path = "blah"
`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "server core configuration must contain trust_domain")
	})

	s.T().Run("missing ca_bundle_path and ca_bundle_paths", func(t *testing.T) {
		err := doConfig(t, coreConfig, "")
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "ca_bundle_path or ca_bundle_paths must be configured")
	})

	s.T().Run("ca_bundle_path and ca_bundle_path configured", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		ca_bundle_path = "blah"
		ca_bundle_paths = ["blah"]
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "only one of ca_bundle_path or ca_bundle_paths can be configured, not both")
	})

	s.T().Run("bad ca_bundle_path", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		ca_bundle_path = "blah"
		`)
		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "unable to load trust bundle")
	})

	s.T().Run("bad ca_bundle_paths", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		ca_bundle_paths = ["blah"]
		`)

		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "unable to load trust bundle")
	})

	s.T().Run("bad mode and ca_bundle_paths", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		mode = "spiffe"
		ca_bundle_paths = ["blah"]
		`)

		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "you can not use ca_bundle_path or ca_bundle_paths in spiffe mode")
	})

	s.T().Run("bad mode and ca_bundle_path", func(t *testing.T) {
		err := doConfig(t, coreConfig, `
		mode = "spiffe"
		ca_bundle_path = "blah"
		`)

		spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "you can not use ca_bundle_path or ca_bundle_paths in spiffe mode")
	})
}

func (s *Suite) loadPlugin(t *testing.T, config string) nodeattestor.NodeAttestor {
	return s.loadPluginFull(t, config, nil)
}

func (s *Suite) loadPluginFull(t *testing.T, config string, identityProvider *fakeidentityprovider.IdentityProvider) nodeattestor.NodeAttestor {
	v1 := new(nodeattestor.V1)

	if identityProvider == nil {
		caRaw, err := os.ReadFile(s.rootCertPath)
		if err != nil {
			return nil
		}
		ca, _ := pem.Decode(caRaw)

		bundle := &plugintypes.Bundle{
			X509Authorities: []*plugintypes.X509Certificate{
				{Asn1: ca.Bytes},
			},
		}

		identityProvider = fakeidentityprovider.New()
		identityProvider.AppendBundle(bundle)
	}
	plugintest.Load(t, BuiltIn(), v1,
		plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(identityProvider)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(config),
	)
	return v1
}

func (s *Suite) createConfiguration(bundlePathType, extraConfig string) string {
	switch bundlePathType {
	case "ca_bundle_path":
		return fmt.Sprintf(`
ca_bundle_path = %q 
%s
`, s.rootCertPath, extraConfig)

	case "ca_bundle_paths":
		bundlesPath := fmt.Sprintf("[%q,%q]", s.alternativeBundlePath, s.rootCertPath)
		return fmt.Sprintf(`
ca_bundle_paths = %s 
%s
`, bundlesPath, extraConfig)

	default:
		s.FailNow("Unsupported bundle path type", "type=%q", bundlePathType)
	}

	return ""
}

func (s *Suite) createConfigurationModeSPIFFE(extraConfig string) string {
	return fmt.Sprintf(`
mode = "spiffe"
%s
`, extraConfig)
}

func marshal(t *testing.T, obj any) []byte {
	data, err := json.Marshal(obj)
	require.NoError(t, err)
	return data
}

func unmarshal(t *testing.T, data []byte, obj any) {
	require.NoError(t, json.Unmarshal(data, obj))
}

func expectNoChallenge(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("challenge is not expected")
}
