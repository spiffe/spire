// +build linux

package tpmdevid_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/hashicorp/go-hclog"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	server_devid "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/require"
)

var (
	sim   *tpmsimulator.TPMSimulator
	devID *tpmsimulator.Credential

	tpmDevicePath                 string = "/dev/tpmrm0"
	devIDCertPath                 string
	devIDPrivPath                 string
	devIDPubPath                  string
	devIDMultipleCertificatesPath string

	streamBuilder = nodeattestortest.ServerStream("tpm_devid")
)

// openSimulatedTPM works in the same way than tpmutil.OpenTPM() but it ignores
// the path argument and opens a connection to a simulated TPM.
func openSimulatedTPM(tpmPath string) (io.ReadWriteCloser, error) {
	if tpmPath != tpmDevicePath {
		return nil, errors.New("unable to open TPM")
	}
	return sim, nil
}

func setupSimulator(t *testing.T) {
	// Override OpenTPM fuction to use a simulator instead of a phisical TPM
	tpmutil.OpenTPM = openSimulatedTPM

	// Create a new TPM simulator
	simulator, err := tpmsimulator.New()
	require.NoError(t, err)
	sim = simulator

	// Create DevIDs
	provisioningCA, err := tpmsimulator.CreateProvisioningCA()
	require.NoError(t, err)

	devID, err = sim.GenerateDevID(provisioningCA, tpmsimulator.RSA)
	require.NoError(t, err)

	createDevIDFiles(t)
}

func teardownSimulator(t *testing.T) {
	require.NoError(t, sim.Close())
}

func createDevIDFiles(t *testing.T) {
	dir := t.TempDir()
	devIDCertPath = path.Join(dir, "devid-certificate.pem")
	devIDPrivPath = path.Join(dir, "devid-priv-path")
	devIDPubPath = path.Join(dir, "devid-pub-path")
	devIDMultipleCertificatesPath = path.Join(dir, "devid-multiple-certificates.pem")

	require.NoError(t, ioutil.WriteFile(
		devIDCertPath,
		pemutil.EncodeCertificate(devID.Certificate),
		0600),
	)
	require.NoError(t, ioutil.WriteFile(
		devIDMultipleCertificatesPath,
		pemutil.EncodeCertificates([]*x509.Certificate{devID.Certificate, devID.Certificate}),
		0600),
	)
	require.NoError(t, ioutil.WriteFile(devIDPrivPath, devID.PrivateBlob, 0600))
	require.NoError(t, ioutil.WriteFile(devIDPubPath, devID.PublicBlob, 0600))
}

func TestConfigure(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tests := []struct {
		name               string
		hclConf            string
		expErr             string
		autoDetectTPMFails bool
	}{
		{
			name:    "Configure fails if receives wrong HCL configuration",
			hclConf: "not HCL conf",
			expErr:  "rpc error: code = InvalidArgument desc = unable to decode configuration",
		},
		{
			name:    "Configure fails if DevID certificate path is empty",
			hclConf: "",
			expErr:  "rpc error: code = InvalidArgument desc = missing configurable: devid_cert_path is required",
		},
		{
			name:    "Configure fails if DevID private key path is empty",
			hclConf: `devid_cert_path = "non-existent-path/to/devid.cert"`,
			expErr:  "rpc error: code = InvalidArgument desc = missing configurable: devid_priv_path is required",
		},
		{
			name: "Configure fails if DevID public key path is empty",
			hclConf: `	devid_cert_path = "non-existent-path/to/devid.cert" 
						devid_priv_path = "non-existent-path/to/devid-private-blob"`,
			expErr: "rpc error: code = InvalidArgument desc = missing configurable: devid_pub_path is required",
		},
		{
			name: "Configure fails if DevID certificate cannot be opened",
			hclConf: `	devid_cert_path = "non-existent-path/to/devid.cert" 
						devid_priv_path = "non-existent-path/to/devid-private-blob"
						devid_pub_path = "non-existent-path/to/devid-public-blob"
						tpm_device_path = "/dev/tpmrm0"`,
			expErr: "rpc error: code = Internal desc = unable to load DevID files: cannot load certificate: open non-existent-path/to/devid.cert: no such file or directory",
		},
		{
			name: "Configure fails if TPM path is not provided and it cannot be auto detected",
			hclConf: `devid_cert_path = "non-existent-path/to/devid.cert" 
					devid_priv_path = "non-existent-path/to/devid-private-blob"
					devid_pub_path = "non-existent-path/to/devid-public-blob"`,
			expErr:             "rpc error: code = InvalidArgument desc = unable to autodetect TPM",
			autoDetectTPMFails: true,
		},
		{
			name: "Configure fails if more than one DevID certificate is provided",
			hclConf: fmt.Sprintf(`devid_cert_path = %q 
						devid_priv_path = "non-existent-path/to/devid-private-blob"
						devid_pub_path = "non-existent-path/to/devid-public-blob"
						tpm_device_path = "/dev/tpmrm0"`, devIDMultipleCertificatesPath),
			expErr: "rpc error: code = Internal desc = unable to load DevID files: only one certificate is expected",
		},
		{
			name: "Configure fails if DevID private key cannot be opened",
			hclConf: fmt.Sprintf(`devid_cert_path = %q 
						devid_priv_path = "non-existent-path/to/devid-private-blob"
						devid_pub_path = "non-existent-path/to/devid-public-blob"
						tpm_device_path = "/dev/tpmrm0"`, devIDCertPath),
			expErr: "rpc error: code = Internal desc = unable to load DevID files: cannot load private key: open non-existent-path/to/devid-private-blob: no such file or directory",
		},
		{
			name: "Configure fails if DevID public key cannot be opened",
			hclConf: fmt.Sprintf(`devid_cert_path = %q 
						devid_priv_path = %q
						devid_pub_path = "non-existent-path/to/devid-public-blob"
						tpm_device_path = "/dev/tpmrm0"`,
				devIDCertPath,
				devIDPrivPath),
			expErr: "rpc error: code = Internal desc = unable to load DevID files: cannot load public key: open non-existent-path/to/devid-public-blob: no such file or directory",
		},
		{
			name: "Configure succeeds providing a TPM path",
			hclConf: fmt.Sprintf(`devid_cert_path = %q 
						devid_priv_path = %q
						devid_pub_path = %q
						tpm_device_path = "/dev/tpmrm0"`,
				devIDCertPath,
				devIDPrivPath,
				devIDPubPath),
		},
		{
			name: "Configure succeeds auto detecting the TPM path",
			hclConf: fmt.Sprintf(`devid_cert_path = %q 
						devid_priv_path = %q
						devid_pub_path = %q`,
				devIDCertPath,
				devIDPrivPath,
				devIDPubPath),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tpmdevid.AutoDetectTPMPath = func(string) (string, error) {
				if tt.autoDetectTPMFails {
					return "", errors.New("unable to autodetect TPM")
				}
				return "/dev/tpmrm0", nil
			}

			plugin := tpmdevid.New()
			resp, err := plugin.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: tt.hclConf})
			if tt.expErr != "" {
				require.Contains(t, err.Error(), tt.expErr)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestAidAttestationFailiures(t *testing.T) {
	tests := []struct {
		name         string
		openTPMFail  bool
		getEKFail    bool
		expErr       string
		serverStream nodeattestor.ServerStream
	}{
		{
			name:         "AidAttestation fails if a new session cannot be started",
			expErr:       `rpc error: code = Internal desc = nodeattestor(tpm_devid): unable start a new TPM session: cannot load DevID: failed to load key on TPM`,
			openTPMFail:  true,
			serverStream: streamBuilder.Build(),
		},
		{
			name:         "AidAttestation fails if EK certificate cannot be get",
			expErr:       "rpc error: code = Internal desc = nodeattestor(tpm_devid): unable to get endorsement certificate",
			getEKFail:    true,
			serverStream: streamBuilder.Build(),
		},
		{
			name:         "AidAttestation fails if server does not sends a challenge",
			expErr:       "the error",
			serverStream: streamBuilder.FailAndBuild(errors.New("the error")),
		},
		{
			name:         "AidAttestation fails if agent cannot unmarshall server challenge",
			expErr:       "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): unable to unmarshall challenges",
			serverStream: streamBuilder.IgnoreThenChallenge([]byte("not-a-challenge")).Build(),
		},
		{
			name:   "AidAttestation fails if agent fails to solve proof of possession challenge",
			expErr: "rpc error: code = Internal desc = nodeattestor(tpm_devid): unable to solve proof of possession challenge: failed to sign nonce",
			serverStream: func() nodeattestor.ServerStream {
				challenges, err := json.Marshal(common_devid.ChallengeRequest{
					DevID: make([]byte, 1025), //TPM cannot sign payloads that contains more than 1024 bytes
				})
				require.NoError(t, err)
				return streamBuilder.IgnoreThenChallenge(challenges).Build()
			}(),
		},
		{
			name:   "AidAttestation fails if server does not send a proof of residency challenge",
			expErr: "rpc error: code = Internal desc = nodeattestor(tpm_devid): received empty credential activation challenge from server",
			serverStream: func() nodeattestor.ServerStream {
				challenges, err := json.Marshal(common_devid.ChallengeRequest{
					DevID:          make([]byte, 1024),
					CredActivation: nil,
				})
				require.NoError(t, err)
				return streamBuilder.IgnoreThenChallenge(challenges).Build()
			}(),
		},
		{
			name:   "AidAttestation fails if agent fails to solve proof of residency challenge",
			expErr: "rpc error: code = Internal desc = nodeattestor(tpm_devid): unable to solve proof of residency challenge",
			serverStream: func() nodeattestor.ServerStream {
				challenges, err := json.Marshal(common_devid.ChallengeRequest{
					DevID: make([]byte, 1024),
					CredActivation: &common_devid.CredActivation{
						Credential: []byte("wrong formatted credential"),
						Secret:     []byte("wrong formatted secret"),
					},
				})
				require.NoError(t, err)
				return streamBuilder.IgnoreThenChallenge(challenges).Build()
			}(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			setupSimulator(t)
			defer teardownSimulator(t)

			if tt.getEKFail {
				// Remove EK cert from TPM
				require.NoError(t, tpm2.NVUndefineSpace(sim, "", tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA))
			}
			if tt.openTPMFail {
				// Do a manufacture reset to reset seeds so key cannot be loaded
				sim.ManufactureReset()
			}

			p := loadAndConfigurePlugin(t)
			err := p.Attest(context.Background(), tt.serverStream)
			if tt.expErr != "" {
				require.Contains(t, err.Error(), tt.expErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAidAttestationSucceeds(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	// Override tpmdevid.NewSession() with a local function that returns a
	// pointer to the TPM session.
	var session *tpmutil.Session
	var newSession = func(scfg *tpmutil.SessionConfig) (*tpmutil.Session, error) {
		if session != nil {
			return session, nil
		}
		s, err := tpmutil.NewSession(scfg)
		session = s
		return session, err
	}
	tpmdevid.NewSession = newSession

	// Pregenerate a new session so we can have access to the session object
	// The tpmdevid.NewSession() function will return a pointer to this session
	session, err := newSession(&tpmutil.SessionConfig{
		DevicePath: tpmDevicePath,
		DevIDPriv:  devID.PrivateBlob,
		DevIDPub:   devID.PublicBlob,
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)

	// Extract data required to create the challenges
	akPub, err := tpm2.DecodePublic(session.GetAKPublic())
	require.NoError(t, err)

	ekPubBytes, err := session.GetEKPublic()
	require.NoError(t, err)
	ekPub, err := tpm2.DecodePublic(ekPubBytes)
	require.NoError(t, err)

	// Create proof of residency challenge
	porChallenge, porChallengeExp, err := server_devid.NewCredActivationChallenge(akPub, ekPub)
	require.NoError(t, err)

	// Create proof of possession challenge
	popChallenge := []byte("nonce")

	challenges, err := json.Marshal(common_devid.ChallengeRequest{
		DevID:          popChallenge,
		CredActivation: porChallenge,
	})
	require.NoError(t, err)

	// Create handle that verifies the challenge responses
	ss := streamBuilder.IgnoreThenChallenge(challenges).
		Handle(func(challengeResponse []byte) ([]byte, error) {
			response := new(common_devid.ChallengeResponse)
			if err := json.Unmarshal(challengeResponse, response); err != nil {
				return nil, err
			}

			err := server_devid.VerifyDevIDChallenge(devID.Certificate, popChallenge, response.DevID)
			if err != nil {
				return nil, err
			}

			err = server_devid.VerifyCredActivationChallenge(porChallengeExp, response.CredActivation)
			if err != nil {
				return nil, err
			}

			return nil, nil
		}).Build()

	// Configure and run the attestor
	p := loadAndConfigurePlugin(t)
	err = p.Attest(context.Background(), ss)
	require.NoError(t, err)
}

func loadAndConfigurePlugin(t *testing.T) nodeattestor.NodeAttestor {
	config := fmt.Sprintf(`
		tpm_device_path = %q	 
		devid_cert_path = %q
		devid_priv_path = %q
		devid_pub_path = %q`,
		tpmDevicePath,
		devIDCertPath,
		devIDPrivPath,
		devIDPubPath)

	return loadPlugin(t, plugintest.Configure(config))
}

func loadPlugin(t *testing.T, options ...plugintest.Option) nodeattestor.NodeAttestor {
	na := new(nodeattestor.V1)
	plugintest.Load(t, tpmdevid.BuiltIn(), na, options...)
	return na
}
