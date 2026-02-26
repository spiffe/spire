package tailscale

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	common "github.com/spiffe/spire/pkg/common/plugin/tailscale"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	spirecommon "github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testTailnet  = "example.ts.net"
	testHostname = "mynode.example.ts.net"
	testNodeID   = "n1234567890"
	testOS       = "linux"
	testUser     = "user@example.com"
	testAPIKey   = "tskey-api-test"
)

var (
	testAddresses = []string{"100.64.0.1", "fd7a:115c:a1e0::1"}
	testTags      = []string{"server", "production"}
)

func TestTailscaleAttestor(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	dir        string
	rootCert   *x509.Certificate
	rootKey    crypto.Signer
	interCert  *x509.Certificate
	interKey   crypto.Signer
	leafCert   *x509.Certificate
	leafKey    crypto.Signer
	leafDER    [][]byte // DER-encoded chain: [leaf, intermediate]
	caBundPath string
	agentStore *fakeagentstore.AgentStore
}

func (s *Suite) SetupTest() {
	s.dir = s.T().TempDir()
	s.agentStore = fakeagentstore.New()
	s.createCertChain()
}

func (s *Suite) createCertChain() {
	t := s.T()
	now := time.Now()

	// Create root CA
	rootKey := testkey.NewEC256(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	s.rootCert = rootCert
	s.rootKey = rootKey

	// Create intermediate CA
	interKey := testkey.NewEC256(t)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, interKey.Public(), rootKey)
	require.NoError(t, err)
	interCert, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)
	s.interCert = interCert
	s.interKey = interKey

	// Create leaf cert with Tailscale-like DNS SAN
	leafKey := testkey.NewEC256(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: testHostname},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{testHostname},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, leafKey.Public(), interKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	s.leafCert = leafCert
	s.leafKey = leafKey
	s.leafDER = [][]byte{leafDER, interDER}

	// Write root CA bundle to PEM file
	s.caBundPath = filepath.Join(s.dir, "ca-bundle.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	require.NoError(t, os.WriteFile(s.caBundPath, pemBytes, 0o600))
}

// TestErrorWhenNotConfigured verifies that attestation fails when the plugin is not configured.
func (s *Suite) TestErrorWhenNotConfigured() {
	attestor := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(New()), attestor,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
	)

	payload := s.makePayload(s.leafDER)
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.FailedPrecondition, "not configured")
	s.Require().Nil(result)
}

// TestErrorOnMissingPayload verifies that attestation fails with no payload.
func (s *Suite) TestErrorOnMissingPayload() {
	attestor := s.loadPlugin(s.defaultConfig())
	result, err := attestor.Attest(context.Background(), nil, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "payload cannot be empty")
	s.Require().Nil(result)
}

// TestErrorOnBadPayload verifies that attestation fails with invalid JSON.
func (s *Suite) TestErrorOnBadPayload() {
	attestor := s.loadPlugin(s.defaultConfig())
	result, err := attestor.Attest(context.Background(), []byte("not json"), expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "failed to unmarshal data")
	s.Require().Nil(result)
}

// TestErrorOnNoCertificate verifies that attestation fails with empty cert list.
func (s *Suite) TestErrorOnNoCertificate() {
	attestor := s.loadPlugin(s.defaultConfig())
	payload := s.makePayload(nil)
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "no certificate to attest")
	s.Require().Nil(result)
}

// TestErrorOnMalformedLeaf verifies that attestation fails with a malformed leaf cert.
func (s *Suite) TestErrorOnMalformedLeaf() {
	attestor := s.loadPlugin(s.defaultConfig())
	payload := s.makePayload([][]byte{{0x00}})
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "unable to parse leaf certificate")
	s.Require().Nil(result)
}

// TestErrorOnMalformedIntermediate verifies that attestation fails with a malformed intermediate.
func (s *Suite) TestErrorOnMalformedIntermediate() {
	attestor := s.loadPlugin(s.defaultConfig())
	payload := s.makePayload([][]byte{s.leafDER[0], {0x00}})
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "unable to parse intermediate certificate 0")
	s.Require().Nil(result)
}

// TestErrorOnCertVerificationFailure verifies that attestation fails when the cert chain is untrusted.
func (s *Suite) TestErrorOnCertVerificationFailure() {
	attestor := s.loadPlugin(s.defaultConfig())
	// Use only the leaf (no intermediate) so chain verification fails
	payload := s.makePayload(s.leafDER[:1])
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "certificate verification failed")
	s.Require().Nil(result)
}

// TestErrorOnHostnameMismatch verifies that attestation fails when the cert SAN doesn't match the tailnet.
func (s *Suite) TestErrorOnHostnameMismatch() {
	leafDER, _ := s.createLeafWithHostname("wrongnode.other.ts.net")

	attestor := s.loadPlugin(s.defaultConfig())
	payload := s.makePayload(leafDER)
	result, err := attestor.Attest(context.Background(), payload, expectNoChallenge)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "hostname validation failed")
	s.Require().Nil(result)
}

// TestErrorOnChallengeResponseFailure verifies that attestation fails with an invalid challenge response.
func (s *Suite) TestErrorOnChallengeResponseFailure() {
	attestor := s.loadPluginWithClient(s.defaultConfig(), s.defaultFakeClient())
	payload := s.makePayload(s.leafDER)

	// Return an empty (invalid) challenge response
	badChallengeFn := func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("{}"), nil
	}

	result, err := attestor.Attest(context.Background(), payload, badChallengeFn)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "challenge response verification failed")
	s.Require().Nil(result)
}

// TestErrorOnMalformedChallengeResponse verifies handling of unmarshalable response.
func (s *Suite) TestErrorOnMalformedChallengeResponse() {
	attestor := s.loadPluginWithClient(s.defaultConfig(), s.defaultFakeClient())
	payload := s.makePayload(s.leafDER)

	badChallengeFn := func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("not json"), nil
	}

	result, err := attestor.Attest(context.Background(), payload, badChallengeFn)
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.InvalidArgument, "unable to unmarshal challenge response")
	s.Require().Nil(result)
}

// TestErrorOnDeviceNotFound verifies that attestation fails when the device is not in the API.
func (s *Suite) TestErrorOnDeviceNotFound() {
	fakeClient := &fakeTailscaleClient{
		err: fmt.Errorf("device with hostname %q not found in tailnet %q", testHostname, testTailnet),
	}
	attestor := s.loadPluginWithClient(s.defaultConfig(), fakeClient)
	payload := s.makePayload(s.leafDER)

	result, err := attestor.Attest(context.Background(), payload, s.challengeFn())
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.Internal, "failed to query Tailscale API")
	s.Require().Nil(result)
}

// TestErrorOnDeviceNotAuthorized verifies that attestation fails when the device is not authorized.
func (s *Suite) TestErrorOnDeviceNotAuthorized() {
	info := s.defaultDeviceInfo()
	info.Authorized = false
	fakeClient := &fakeTailscaleClient{device: info}
	attestor := s.loadPluginWithClient(s.defaultConfig(), fakeClient)
	payload := s.makePayload(s.leafDER)

	result, err := attestor.Attest(context.Background(), payload, s.challengeFn())
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "not authorized")
	s.Require().Nil(result)
}

// TestErrorOnAttestedBefore verifies TOFU enforcement.
func (s *Suite) TestErrorOnAttestedBefore() {
	fakeClient := &fakeTailscaleClient{device: s.defaultDeviceInfo()}
	attestor := s.loadPluginWithClient(s.defaultConfig(), fakeClient)

	agentID := fmt.Sprintf("spiffe://example.org/spire/agent/tailscale/%s", testNodeID)
	s.agentStore.SetAgentInfo(&agentstorev1.AgentInfo{
		AgentId: agentID,
	})

	payload := s.makePayload(s.leafDER)
	result, err := attestor.Attest(context.Background(), payload, s.challengeFn())
	spiretest.RequireGRPCStatusContains(s.T(), err, codes.PermissionDenied, "attestation data has already been used to attest an agent")
	s.Require().Nil(result)
}

// TestAttestSuccess verifies the full successful attestation flow.
func (s *Suite) TestAttestSuccess() {
	fakeClient := &fakeTailscaleClient{device: s.defaultDeviceInfo()}
	attestor := s.loadPluginWithClient(s.defaultConfig(), fakeClient)
	payload := s.makePayload(s.leafDER)

	result, err := attestor.Attest(context.Background(), payload, s.challengeFn())
	s.Require().NoError(err)
	s.Require().NotNil(result)

	expectedAgentID := fmt.Sprintf("spiffe://example.org/spire/agent/tailscale/%s", testNodeID)
	s.Require().Equal(expectedAgentID, result.AgentID)
	s.Require().True(result.CanReattest)

	expectedSelectors := []*spirecommon.Selector{
		{Type: "tailscale", Value: "hostname:mynode"},
		{Type: "tailscale", Value: "tag:server"},
		{Type: "tailscale", Value: "tag:production"},
		{Type: "tailscale", Value: "os:linux"},
		{Type: "tailscale", Value: "address:100.64.0.1"},
		{Type: "tailscale", Value: "address:fd7a:115c:a1e0::1"},
		{Type: "tailscale", Value: "user:user@example.com"},
		{Type: "tailscale", Value: "authorized:true"},
	}
	commonutil.SortSelectors(expectedSelectors)
	commonutil.SortSelectors(result.Selectors)
	spiretest.AssertProtoListEqual(s.T(), expectedSelectors, result.Selectors)
}

// TestAttestSuccessWithCustomTemplate verifies that custom agent path templates work.
func (s *Suite) TestAttestSuccessWithCustomTemplate() {
	config := fmt.Sprintf(`
ca_bundle_path = %q
tailnet = %q
api_key = %q
agent_path_template = "/{{ .Hostname }}"
`, s.caBundPath, testTailnet, testAPIKey)
	fakeClient := &fakeTailscaleClient{device: s.defaultDeviceInfo()}
	attestor := s.loadPluginWithClient(config, fakeClient)
	payload := s.makePayload(s.leafDER)

	result, err := attestor.Attest(context.Background(), payload, s.challengeFn())
	s.Require().NoError(err)
	s.Require().NotNil(result)

	expectedAgentID := "spiffe://example.org/spire/agent/mynode"
	s.Require().Equal(expectedAgentID, result.AgentID)
}

// TestAttestSuccessMinimalSelectors verifies selectors when device has minimal info.
func (s *Suite) TestAttestSuccessMinimalSelectors() {
	info := &common.DeviceInfo{
		NodeID:     testNodeID,
		Hostname:   "mynode",
		Tailnet:    testTailnet,
		Authorized: true,
	}
	fakeClient := &fakeTailscaleClient{device: info}
	attestor := s.loadPluginWithClient(s.defaultConfig(), fakeClient)
	payload := s.makePayload(s.leafDER)

	result, err := attestor.Attest(context.Background(), payload, s.challengeFn())
	s.Require().NoError(err)
	s.Require().NotNil(result)

	expectedSelectors := []*spirecommon.Selector{
		{Type: "tailscale", Value: "hostname:mynode"},
		{Type: "tailscale", Value: "authorized:true"},
	}
	commonutil.SortSelectors(expectedSelectors)
	commonutil.SortSelectors(result.Selectors)
	spiretest.AssertProtoListEqual(s.T(), expectedSelectors, result.Selectors)
}

// TestConfigure tests configuration validation.
func (s *Suite) TestConfigure() {
	doConfig := func(t *testing.T, coreConfig catalog.CoreConfig, config string) error {
		var err error
		plugintest.Load(t, BuiltIn(), nil,
			plugintest.CaptureConfigureError(&err),
			plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
			plugintest.CoreConfig(coreConfig),
			plugintest.Configure(config),
		)
		return err
	}

	coreConfig := catalog.CoreConfig{
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}

	s.T().Run("malformed HCL", func(t *testing.T) {
		err := doConfig(t, coreConfig, "bad juju")
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "unable to decode configuration")
	})

	s.T().Run("missing trust domain", func(t *testing.T) {
		err := doConfig(t, catalog.CoreConfig{}, fmt.Sprintf(`
ca_bundle_path = %q
tailnet = %q
api_key = %q
`, s.caBundPath, testTailnet, testAPIKey))
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "server core configuration must contain trust_domain")
	})

	s.T().Run("missing ca_bundle_path", func(t *testing.T) {
		err := doConfig(t, coreConfig, fmt.Sprintf(`
tailnet = %q
api_key = %q
`, testTailnet, testAPIKey))
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "ca_bundle_path is required")
	})

	s.T().Run("missing tailnet", func(t *testing.T) {
		err := doConfig(t, coreConfig, fmt.Sprintf(`
ca_bundle_path = %q
api_key = %q
`, s.caBundPath, testAPIKey))
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "tailnet is required")
	})

	s.T().Run("missing api_key", func(t *testing.T) {
		err := doConfig(t, coreConfig, fmt.Sprintf(`
ca_bundle_path = %q
tailnet = %q
`, s.caBundPath, testTailnet))
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "api_key is required")
	})

	s.T().Run("bad ca_bundle_path", func(t *testing.T) {
		err := doConfig(t, coreConfig, fmt.Sprintf(`
ca_bundle_path = "/nonexistent/path.pem"
tailnet = %q
api_key = %q
`, testTailnet, testAPIKey))
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "unable to load trust bundle")
	})

	s.T().Run("bad agent_path_template", func(t *testing.T) {
		err := doConfig(t, coreConfig, fmt.Sprintf(`
ca_bundle_path = %q
tailnet = %q
api_key = %q
agent_path_template = "/{{ .NodeID "
`, s.caBundPath, testTailnet, testAPIKey))
		spiretest.AssertGRPCStatusContains(t, err, codes.InvalidArgument, "failed to parse agent path template")
	})

	s.T().Run("success", func(t *testing.T) {
		err := doConfig(t, coreConfig, s.defaultConfig())
		require.NoError(t, err)
	})
}

// Helpers

func (s *Suite) defaultConfig() string {
	return fmt.Sprintf(`
ca_bundle_path = %q
tailnet = %q
api_key = %q
`, s.caBundPath, testTailnet, testAPIKey)
}

func (s *Suite) defaultDeviceInfo() *common.DeviceInfo {
	return &common.DeviceInfo{
		NodeID:     testNodeID,
		Hostname:   "mynode",
		Tailnet:    testTailnet,
		Tags:       testTags,
		OS:         testOS,
		Addresses:  testAddresses,
		User:       testUser,
		Authorized: true,
	}
}

func (s *Suite) defaultFakeClient() *fakeTailscaleClient {
	return &fakeTailscaleClient{device: s.defaultDeviceInfo()}
}

func (s *Suite) loadPlugin(config string) nodeattestor.NodeAttestor {
	return s.loadPluginWithClient(config, nil)
}

func (s *Suite) loadPluginWithClient(config string, client tailscaleClient) nodeattestor.NodeAttestor {
	p := New()
	if client != nil {
		p.hooks.newClient = func(_, _ string) tailscaleClient {
			return client
		}
	}

	v1 := new(nodeattestor.V1)
	plugintest.Load(s.T(), builtin(p), v1,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(s.agentStore)),
		plugintest.Configure(config),
	)
	return v1
}

func (s *Suite) makePayload(certs [][]byte) []byte {
	data := &common.AttestationData{
		Certificates: certs,
	}
	payload, err := json.Marshal(data)
	s.Require().NoError(err)
	return payload
}

func (s *Suite) challengeFn() func(ctx context.Context, challenge []byte) ([]byte, error) {
	return func(_ context.Context, challenge []byte) ([]byte, error) {
		popChallenge := new(x509pop.Challenge)
		if err := json.Unmarshal(challenge, popChallenge); err != nil {
			return nil, err
		}
		response, err := x509pop.CalculateResponse(s.leafKey, popChallenge)
		if err != nil {
			return nil, err
		}
		return json.Marshal(response)
	}
}

// createLeafWithHostname creates a leaf cert chain with the given hostname in the SAN,
// signed by the suite's intermediate CA. Returns [leafDER, intermediateDER] and the leaf key.
func (s *Suite) createLeafWithHostname(hostname string) ([][]byte, crypto.Signer) {
	t := s.T()
	now := time.Now()
	key := testkey.NewEC256(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{hostname},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.interCert, key.Public(), s.interKey)
	require.NoError(t, err)

	// Reuse the same intermediate DER
	return [][]byte{leafDER, s.leafDER[1]}, key
}

// fakeTailscaleClient is a test double for the Tailscale API client.
type fakeTailscaleClient struct {
	device *common.DeviceInfo
	err    error
}

func (f *fakeTailscaleClient) getDeviceByHostname(_ context.Context, _, _ string) (*common.DeviceInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.device, nil
}

func expectNoChallenge(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("challenge is not expected")
}
