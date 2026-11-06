package x509pop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/fixture"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// legacyChallenge mirrors the challenge representation of agents that predate
// hash selection, which do not know about the hash field.
type legacyChallenge struct {
	RSASignature   *x509pop.RSASignatureChallenge   `json:"rsa_signature"`
	ECDSASignature *x509pop.ECDSASignatureChallenge `json:"ecdsa_signature"`
}

type challengeResponder func(t *testing.T, key crypto.Signer, challenge []byte) []byte

// newAgentResponder responds the way an agent with hash selection support does.
func newAgentResponder(t *testing.T, key crypto.Signer, challengeBytes []byte) []byte {
	challenge := new(x509pop.Challenge)
	unmarshal(t, challengeBytes, challenge)
	response, err := x509pop.CalculateResponse(key, challenge)
	require.NoError(t, err)
	return marshal(t, response)
}

// legacyAgentResponder reproduces agents that predate hash selection: the
// hash field is not parsed and the combined nonces are always signed with
// SHA-256.
func legacyAgentResponder(t *testing.T, key crypto.Signer, challengeBytes []byte) []byte {
	challenge := new(legacyChallenge)
	unmarshal(t, challengeBytes, challenge)
	response := new(x509pop.Response)
	var err error
	switch key := key.(type) {
	case *rsa.PrivateKey:
		response.RSASignature, err = x509pop.CalculateRSASignatureResponse(key, challenge.RSASignature)
	case *ecdsa.PrivateKey:
		response.ECDSASignature, err = x509pop.CalculateECDSASignatureResponse(key, challenge.ECDSASignature)
	default:
		require.FailNow(t, "unexpected key type")
	}
	require.NoError(t, err)
	return marshal(t, response)
}

func TestAttestHashAlgorithm(t *testing.T) {
	ca := newExtTestCA(t)

	keys := []struct {
		name string
		key  crypto.Signer
	}{
		{name: "RSA-2048", key: testkey.MustRSA2048()},
		{name: "ECDSA-P256", key: testkey.MustEC256()},
		{name: "ECDSA-P384", key: testkey.MustEC384()},
	}

	tests := []struct {
		desc           string
		config         string
		responder      challengeResponder
		expectWireHash string
		expectErr      string
	}{
		{
			desc:      "default (sha256) with new agent",
			responder: newAgentResponder,
		},
		{
			desc:      "default (sha256) with legacy agent",
			responder: legacyAgentResponder,
		},
		{
			desc:      "explicit sha256 with new agent",
			config:    `hash_algorithm = "sha256"`,
			responder: newAgentResponder,
		},
		{
			desc:      "explicit sha256 with legacy agent",
			config:    `hash_algorithm = "sha256"`,
			responder: legacyAgentResponder,
		},
		{
			desc:           "sha384 with new agent",
			config:         `hash_algorithm = "sha384"`,
			responder:      newAgentResponder,
			expectWireHash: x509pop.HashSHA384,
		},
		{
			desc:           "sha384 rejects legacy sha256 agent",
			config:         `hash_algorithm = "sha384"`,
			responder:      legacyAgentResponder,
			expectWireHash: x509pop.HashSHA384,
			expectErr:      "nodeattestor(x509pop): challenge response verification failed",
		},
	}

	for _, key := range keys {
		leafDER := ca.issueLeaf(t, key.key)
		for _, tt := range tests {
			t.Run(key.name+"/"+tt.desc, func(t *testing.T) {
				attestor := loadHashTestPlugin(t, ca.path, tt.config)
				payload := marshal(t, &x509pop.AttestationData{Certificates: [][]byte{leafDER}})

				result, err := attestor.Attest(context.Background(), payload, func(_ context.Context, challenge []byte) ([]byte, error) {
					fields := map[string]json.RawMessage{}
					unmarshal(t, challenge, &fields)
					if tt.expectWireHash == "" {
						require.NotContains(t, fields, "hash", "SHA-256 challenges must keep the legacy wire format")
					} else {
						require.JSONEq(t, fmt.Sprintf("%q", tt.expectWireHash), string(fields["hash"]))
					}
					return tt.responder(t, key.key, challenge), nil
				})
				if tt.expectErr != "" {
					spiretest.RequireGRPCStatusContains(t, err, codes.PermissionDenied, tt.expectErr)
					require.Nil(t, result)
					return
				}
				require.NoError(t, err)
				require.Equal(t, "spiffe://example.org/spire/agent/x509pop/node1.example.org", result.AgentID)
			})
		}
	}
}

func TestAttestHashAlgorithmIgnoresResponseSelection(t *testing.T) {
	// The response cannot influence the hash used for verification: a response
	// carrying an unexpected "hash" field and a SHA-256 signature is still
	// rejected by a server requiring SHA-384.
	ca := newExtTestCA(t)
	key := testkey.MustEC256()
	leafDER := ca.issueLeaf(t, key)
	attestor := loadHashTestPlugin(t, ca.path, `hash_algorithm = "sha384"`)
	payload := marshal(t, &x509pop.AttestationData{Certificates: [][]byte{leafDER}})

	result, err := attestor.Attest(context.Background(), payload, func(_ context.Context, challengeBytes []byte) ([]byte, error) {
		challenge := new(x509pop.Challenge)
		unmarshal(t, challengeBytes, challenge)
		require.Equal(t, x509pop.HashSHA384, challenge.Hash)
		challenge.Hash = x509pop.HashSHA256
		response, err := x509pop.CalculateResponse(key, challenge)
		require.NoError(t, err)

		fields := map[string]any{}
		unmarshal(t, marshal(t, response), &fields)
		fields["hash"] = x509pop.HashSHA256
		return marshal(t, fields), nil
	})
	spiretest.RequireGRPCStatusContains(t, err, codes.PermissionDenied, "challenge response verification failed")
	require.Nil(t, result)
}

func TestConfigureHashAlgorithm(t *testing.T) {
	caPath := fixture.Join("nodeattestor", "x509pop", "root-crt.pem")
	doConfig := func(t *testing.T, extra string) error {
		var err error
		plugintest.Load(t, BuiltIn(), nil,
			plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(fakeidentityprovider.New())),
			plugintest.CaptureConfigureError(&err),
			plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
			plugintest.Configure(fmt.Sprintf("ca_bundle_path = %q\n%s", caPath, extra)),
		)
		return err
	}

	for _, valid := range []string{"", `hash_algorithm = ""`, `hash_algorithm = "sha256"`, `hash_algorithm = "sha384"`} {
		t.Run("valid "+valid, func(t *testing.T) {
			require.NoError(t, doConfig(t, valid))
		})
	}
	for _, invalid := range []string{"sha512", "sha1", "md5", "SHA384", "sha-384", " sha384"} {
		t.Run("invalid "+invalid, func(t *testing.T) {
			err := doConfig(t, fmt.Sprintf("hash_algorithm = %q", invalid))
			spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, fmt.Sprintf("invalid hash_algorithm %q", invalid))
		})
	}
}

func loadHashTestPlugin(t *testing.T, caPath, extra string) nodeattestor.NodeAttestor {
	v1 := new(nodeattestor.V1)
	plugintest.Load(t, BuiltIn(), v1,
		plugintest.HostServices(identityproviderv1.IdentityProviderServiceServer(fakeidentityprovider.New())),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configure(fmt.Sprintf(`
ca_bundle_path = %q
agent_path_template = "/x509pop/{{ .Subject.CommonName }}"
%s
`, caPath, extra)),
	)
	return v1
}

func (ca *extTestCA) issueLeaf(t *testing.T, key crypto.Signer) []byte {
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x4d8),
		Subject:      pkix.Name{CommonName: "node1.example.org"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.cert, key.Public(), ca.key)
	require.NoError(t, err)
	return leafDER
}
