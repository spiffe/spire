//go:build !darwin

package tpmdevid_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	devIDBundlePath       string
	endorsementBundlePath string

	isWindows = runtime.GOOS == "windows"

	tpmPasswords = tpmutil.TPMPasswords{
		EndorsementHierarchy: "endorsement-hierarchy-pass",
		OwnerHierarchy:       "owner-hierarchy-pass",
		DevIDKey:             "devid-pass",
	}
)

func setupSimulator(t *testing.T, provisioningCA *tpmsimulator.ProvisioningAuthority) *tpmsimulator.TPMSimulator {
	// Creates a new global TPM simulator
	sim, err := tpmsimulator.New(tpmPasswords.EndorsementHierarchy, tpmPasswords.OwnerHierarchy)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, sim.Close(), "unexpected error encountered closing simulator")
	})
	tpmutil.OpenTPM = sim.OpenTPM

	// Create a temporal directory to store configuration files
	dir := t.TempDir()

	// Write provisioning root certificates into temp directory
	devIDBundlePath = path.Join(dir, "devid-provisioning-ca.pem")
	require.NoError(t, os.WriteFile(
		devIDBundlePath,
		pemutil.EncodeCertificate(provisioningCA.RootCert),
		0600),
	)

	// Write endorsement root certificate into temp directory
	endorsementBundlePath = path.Join(dir, "endorsement-ca.pem")
	require.NoError(t, os.WriteFile(
		endorsementBundlePath,
		pemutil.EncodeCertificate(sim.GetEKRoot()),
		0600),
	)
	return sim
}

func TestConfigure(t *testing.T) {
	// Create a provisioning authority to generate DevIDs
	provisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err)

	// Setup the TPM simulator
	setupSimulator(t, provisioningCA)

	tests := []struct {
		name     string
		hclConf  string
		coreConf *configv1.CoreConfiguration
		expErr   string
	}{
		{
			name:   "Configure fails if core config is not provided",
			expErr: "rpc error: code = InvalidArgument desc = core configuration is missing",
		},
		{
			name:     "Configure fails if trust domain is empty",
			expErr:   "rpc error: code = InvalidArgument desc = trust_domain is required",
			coreConf: &configv1.CoreConfiguration{},
		},
		{
			name:     "Configure fails if HCL config cannot be decoded",
			expErr:   "rpc error: code = InvalidArgument desc = unable to decode configuration",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  "not an HCL configuration",
		},
		{
			name:     "Configure fails if devid_ca_path is not provided",
			expErr:   "rpc error: code = InvalidArgument desc = invalid configuration: devid_ca_path is required",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		},
		{
			name:     "Configure fails if endorsement_ca_path is not provided",
			expErr:   "rpc error: code = InvalidArgument desc = invalid configuration: endorsement_ca_path is required",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf:  `devid_ca_path = "non-existent/devid/bundle/path"`,
		},
		{
			name:     "Configure fails if DevID trust bundle cannot be loaded",
			expErr:   "rpc error: code = Internal desc = unable to load DevID trust bundle: open non-existent/devid/bundle/path:",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf: `devid_ca_path = "non-existent/devid/bundle/path"
					  endorsement_ca_path = "non-existent/endorsement/bundle/path"`,
		},
		{
			name:     "Configure fails if endorsement trust bundle cannot be opened",
			expErr:   "rpc error: code = Internal desc = unable to load endorsement trust bundle: open non-existent/endorsement/bundle/path:",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf: fmt.Sprintf(`devid_ca_path = %q
								endorsement_ca_path = "non-existent/endorsement/bundle/path"`,
				devIDBundlePath),
		},
		{
			name:     "Configure succeeds",
			coreConf: &configv1.CoreConfiguration{TrustDomain: "example.org"},
			hclConf: fmt.Sprintf(`devid_ca_path = %q
								endorsement_ca_path = %q`,
				devIDBundlePath,
				endorsementBundlePath),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			plugin := tpmdevid.New()
			resp, err := plugin.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration:  tt.hclConf,
				CoreConfiguration: tt.coreConf,
			})
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

func TestAttestFailiures(t *testing.T) {
	// Create a provisioning authority to generate DevIDs
	provisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err)

	// Generate a DevID signed by the provisioning authority but using
	// another TPM simulator (not the one used in the test)
	anotherSim, err := tpmsimulator.New(tpmPasswords.EndorsementHierarchy, tpmPasswords.OwnerHierarchy)
	require.NoError(t, err)

	devIDAnotherTPM, err := anotherSim.GenerateDevID(provisioningCA, tpmsimulator.RSA, tpmPasswords.DevIDKey)
	require.NoError(t, err)

	// We need to close this TPM simulator before creating a new one (the
	// library only supports one simulator running at the same time)
	anotherSim.Close()

	// Set up the main TPM simulator
	sim := setupSimulator(t, provisioningCA)

	// Generate DevIDs using the main provisioning authority
	devID, err := sim.GenerateDevID(provisioningCA, tpmsimulator.RSA, tpmPasswords.DevIDKey)
	require.NoError(t, err)

	// Create another DevID using the main TPM but signed by a different provisioning authority
	anotherProvisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err)

	devIDAnotherProvisioningCA, err := sim.GenerateDevID(anotherProvisioningCA, tpmsimulator.RSA, tpmPasswords.DevIDKey)
	require.NoError(t, err)

	devicePath := "/dev/tpmrm0"
	if isWindows {
		devicePath = ""
	}
	// Create a TPM session to generate payload and challenge response data
	session, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevicePath: devicePath,
		DevIDPriv:  devID.PrivateBlob,
		DevIDPub:   devID.PublicBlob,
		Passwords:  tpmPasswords,
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)

	ekCert, err := session.GetEKCert()
	require.NoError(t, err)

	ekPub, err := session.GetEKPublic()
	require.NoError(t, err)

	akPub := session.GetAKPublic()

	certifiedDevID, signature, err := session.CertifyDevIDKey()
	require.NoError(t, err)

	// Define common configurations and challenge functions
	goodConf := fmt.Sprintf(`devid_ca_path = %q, endorsement_ca_path = %q`,
		devIDBundlePath, endorsementBundlePath)

	challengeFnNil := func(ctx context.Context, challenge []byte) ([]byte, error) {
		return nil, nil
	}

	tests := []struct {
		name        string
		hclConf     string
		expErr      string
		payload     []byte
		challengeFn func(ctx context.Context, challenge []byte) ([]byte, error)
	}{
		{
			name:        "Attest fails if payload cannot be unmarshalled",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): unable to unmarshall attestation data",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload:     []byte("not a payload"),
		},
		{
			name:        "Attest fails if payload is missing DevID certificate",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): no DevID certificate to attest",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload:     marshalPayload(t, &common_devid.AttestationRequest{}),
		},
		{
			name:        "Attest fails if DevID certificate cannot be parsed",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): unable to parse DevID certificate",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload:     marshalPayload(t, &common_devid.AttestationRequest{DevIDCert: [][]byte{[]byte("not a raw certificate")}}),
		},
		{
			name:        "Attest fails if DevID certificate cannot be chained up to DevID root certificate",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): unable to verify DevID signature: verification failed",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload:     marshalPayload(t, &common_devid.AttestationRequest{DevIDCert: devIDAnotherProvisioningCA.Chain()}),
		},
		{
			name:        "Attest fails if payload is missing the attestation key blob",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): missing attestation key public blob",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload:     marshalPayload(t, &common_devid.AttestationRequest{DevIDCert: devID.Chain()}),
		},
		{
			name:        "Attest fails if payload is missing the DevID key blob",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): missing DevID key public blob",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				AKPub:     akPub,
			}),
		},
		{
			name:        "Attest fails if payload is missing the endorsement certificate",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): missing endorsement certificate",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     akPub,
			}),
		},
		{
			name:        "Attest fails if payload is missing the endorsement key",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): missing endorsement key public blob",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     akPub,
				EKCert:    ekCert,
			}),
		},
		{
			name:        "Attest fails if endorsement certificate cannot be parsed",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): cannot parse endorsement certificate",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     akPub,
				EKCert:    []byte("not-a-certificate"),
				EKPub:     ekPub,
			}),
		},
		{
			name:        "Attest fails if DevID key public blob cannot be decoded",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): cannot decode DevID key public blob",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  []byte("not-a-tpm-public-blob"),
				AKPub:     akPub,
				EKCert:    ekCert,
				EKPub:     ekPub,
			}),
		},
		{
			name:        "Attest fails if attestation key public blob cannot be decoded",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): cannot decode attestation key public blob",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     []byte("not-a-tpm-public-blob"),
				EKCert:    ekCert,
				EKPub:     ekPub,
			}),
		},
		{
			name:        "Attest fails if endorsement key public blob cannot be decoded",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): cannot decode endorsement key public blob",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     akPub,
				EKCert:    ekCert,
				EKPub:     []byte("not-a-tpm-public-blob"),
			}),
		},
		{
			name:        "Attest fails if endorsement key in certificate is different than endorsement key public blob",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): public key in EK certificate differs from public key created via EK template",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     akPub,
				EKCert:    ekCert,
				EKPub:     devID.PublicBlob, // Use DevID public blob (instead of EK) to induce a key missmatch error
			}),
		},
		{
			name:        "Attest fails if endorsement certificate cannot be chained up to the endorsement root",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): cannot verify EK signature",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devID.Chain(),
				DevIDPub:  devID.PublicBlob,
				AKPub:     akPub,
				EKCert:    devID.Certificate.Raw, // Use DevID certificate (instead of EK) to induce a certificate verification error
				EKPub:     devID.PublicBlob,      // Additionally, use DevID public blob (instead of EK) to avoid the key missmatch error
			}),
		},
		{
			name:        "Attest fails if DevID key and attestation key do not reside in the same TPM",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): cannot verify that DevID is in the same TPM than AK",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert: devIDAnotherTPM.Chain(),
				DevIDPub:  devIDAnotherTPM.PublicBlob,
				AKPub:     akPub,
				EKCert:    ekCert,
				EKPub:     ekPub,
			}),
		},
		{
			name:        "Attest fails if the credential activation challenge cannot be generated",
			expErr:      "rpc error: code = Internal desc = nodeattestor(tpm_devid): cannot generate credential activation challenge: cannot extract name from AK public",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert:              devID.Chain(),
				DevIDPub:               devID.PublicBlob,
				EKCert:                 ekCert,
				EKPub:                  ekPub,
				CertifiedDevID:         certifiedDevID,
				CertificationSignature: signature,
				AKPub: func() []byte {
					// Corrupt AK to induce an error that make generation of
					// credential activation challenge to fail.
					akBytes := akPub
					ak, err := tpm2.DecodePublic(akBytes)
					require.NoError(t, err)
					ak.NameAlg = tpm2.AlgNull
					modifiedAKBytes, err := ak.Encode()
					require.NoError(t, err)
					return modifiedAKBytes
				}(),
			}),
		},
		{
			name:    "Attest fails if server fails to receive challenge response",
			expErr:  "unable to respond to challenge",
			hclConf: goodConf,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert:              devID.Chain(),
				DevIDPub:               devID.PublicBlob,
				AKPub:                  akPub,
				EKCert:                 ekCert,
				EKPub:                  ekPub,
				CertifiedDevID:         certifiedDevID,
				CertificationSignature: signature,
			}),
			challengeFn: func(ctx context.Context, challenge []byte) ([]byte, error) {
				return nil, errors.New("unable to respond to challenge")
			},
		},
		{
			name:        "Attest fails if agent sends corrupted challenge response",
			expErr:      "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): unable to unmarshall challenges response:",
			hclConf:     goodConf,
			challengeFn: challengeFnNil,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert:              devID.Chain(),
				DevIDPub:               devID.PublicBlob,
				AKPub:                  akPub,
				EKCert:                 ekCert,
				EKPub:                  ekPub,
				CertifiedDevID:         certifiedDevID,
				CertificationSignature: signature,
			}),
		},
		{
			name:    "Attest fails if agent does not solve proof of possession challenge",
			expErr:  "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): devID challenge verification failed",
			hclConf: goodConf,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert:              devID.Chain(),
				DevIDPub:               devID.PublicBlob,
				AKPub:                  akPub,
				EKCert:                 ekCert,
				EKPub:                  ekPub,
				CertifiedDevID:         certifiedDevID,
				CertificationSignature: signature,
			}),
			challengeFn: func(ctx context.Context, challenge []byte) ([]byte, error) {
				response, err := json.Marshal(common_devid.ChallengeResponse{})
				require.NoError(t, err)
				return response, nil
			},
		},
		{
			name:    "Attest fails if agent does not solve proof of residency challenge",
			expErr:  "rpc error: code = InvalidArgument desc = nodeattestor(tpm_devid): credential activation failed",
			hclConf: goodConf,
			payload: marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert:              devID.Chain(),
				DevIDPub:               devID.PublicBlob,
				AKPub:                  akPub,
				EKCert:                 ekCert,
				EKPub:                  ekPub,
				CertifiedDevID:         certifiedDevID,
				CertificationSignature: signature,
			}),
			challengeFn: func(ctx context.Context, challenge []byte) ([]byte, error) {
				var unmarshalledChallenge common_devid.ChallengeRequest
				err := json.Unmarshal(challenge, &unmarshalledChallenge)
				require.NoError(t, err)

				devIDChallengeResponse, err := session.SolveDevIDChallenge(unmarshalledChallenge.DevID)
				require.NoError(t, err)

				response, err := json.Marshal(common_devid.ChallengeResponse{
					DevID: devIDChallengeResponse,
				})
				require.NoError(t, err)

				return response, nil
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			plugin := loadPlugin(t, tt.hclConf)
			result, err := plugin.Attest(context.Background(), tt.payload, tt.challengeFn)
			require.Contains(t, err.Error(), tt.expErr)
			require.Nil(t, result)
		})
	}
}

func TestAttestSucceeds(t *testing.T) {
	devicePath := "/dev/tpmrm0"
	if isWindows {
		devicePath = ""
	}

	// Create a provisioning authority to generate DevIDs
	provisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err)

	// Setup the main TPM simulator
	sim := setupSimulator(t, provisioningCA)

	// Generate DevIDs with RSA and ECC key types
	devIDRSA, err := sim.GenerateDevID(provisioningCA, tpmsimulator.RSA, tpmPasswords.DevIDKey)
	require.NoError(t, err)
	devIDECC, err := sim.GenerateDevID(provisioningCA, tpmsimulator.ECC, tpmPasswords.DevIDKey)
	require.NoError(t, err)

	// Generate DevIDs with no intermediate certificates
	provisioningCANoIntermediates, err := tpmsimulator.NewProvisioningCA(
		&tpmsimulator.ProvisioningConf{
			NoIntermediates: true,
			RootCertificate: provisioningCA.RootCert,
			RootKey:         provisioningCA.RootKey,
		})
	require.NoError(t, err)
	devIDNoIntermediates, err := sim.GenerateDevID(provisioningCANoIntermediates, tpmsimulator.RSA, tpmPasswords.DevIDKey)
	require.NoError(t, err)

	tests := []struct {
		name              string
		devID             *tpmsimulator.Credential
		expectedAgentID   string
		expectedSelectors []*common.Selector
	}{
		{
			name:  "Attest succeeds for RSA DevID",
			devID: devIDRSA,
			expectedAgentID: fmt.Sprintf("spiffe://example.org/spire/agent/tpm_devid/%v",
				tpmdevid.Fingerprint(devIDRSA.Certificate)),
			expectedSelectors: []*common.Selector{
				{
					Type:  "tpm_devid",
					Value: "subject:cn:devid-leaf",
				},
				{
					Type:  "tpm_devid",
					Value: "issuer:cn:intermediate",
				},
				{
					Type:  "tpm_devid",
					Value: "ca:fingerprint:" + tpmdevid.Fingerprint(devIDRSA.Intermediates[0]),
				},
				{
					Type:  "tpm_devid",
					Value: "ca:fingerprint:" + tpmdevid.Fingerprint(provisioningCA.RootCert),
				},
			},
		},
		{
			name:  "Attest succeeds for ECC DevID",
			devID: devIDECC,
			expectedAgentID: fmt.Sprintf("spiffe://example.org/spire/agent/tpm_devid/%v",
				tpmdevid.Fingerprint(devIDECC.Certificate)),
			expectedSelectors: []*common.Selector{
				{
					Type:  "tpm_devid",
					Value: "subject:cn:devid-leaf",
				},
				{
					Type:  "tpm_devid",
					Value: "issuer:cn:intermediate",
				},
				{
					Type:  "tpm_devid",
					Value: "ca:fingerprint:" + tpmdevid.Fingerprint(devIDECC.Intermediates[0]),
				},
				{
					Type:  "tpm_devid",
					Value: "ca:fingerprint:" + tpmdevid.Fingerprint(provisioningCA.RootCert),
				},
			},
		},
		{
			name:  "Attest succeeds for DevID with no intermediate certificates",
			devID: devIDNoIntermediates,
			expectedAgentID: fmt.Sprintf("spiffe://example.org/spire/agent/tpm_devid/%v",
				tpmdevid.Fingerprint(devIDNoIntermediates.Certificate)),
			expectedSelectors: []*common.Selector{
				{
					Type:  "tpm_devid",
					Value: "subject:cn:devid-leaf",
				},
				{
					Type:  "tpm_devid",
					Value: "issuer:cn:root",
				},
				{
					Type:  "tpm_devid",
					Value: "ca:fingerprint:" + tpmdevid.Fingerprint(provisioningCA.RootCert),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a TPM session to generate payload and challenge response data
			session, err := tpmutil.NewSession(&tpmutil.SessionConfig{
				DevicePath: devicePath,
				DevIDPriv:  tt.devID.PrivateBlob,
				DevIDPub:   tt.devID.PublicBlob,
				Passwords:  tpmPasswords,
				Log:        hclog.NewNullLogger(),
			})
			require.NoError(t, err)
			defer session.Close()

			// Generate payload data
			ekCert, err := session.GetEKCert()
			require.NoError(t, err)
			ekPub, err := session.GetEKPublic()
			require.NoError(t, err)
			certifiedDevID, signature, err := session.CertifyDevIDKey()
			require.NoError(t, err)

			payload := marshalPayload(t, &common_devid.AttestationRequest{
				DevIDCert:              tt.devID.Chain(),
				DevIDPub:               tt.devID.PublicBlob,
				EKCert:                 ekCert,
				EKPub:                  ekPub,
				AKPub:                  session.GetAKPublic(),
				CertifiedDevID:         certifiedDevID,
				CertificationSignature: signature,
			})

			// Generate challenge response data
			challengeFn := func(ctx context.Context, challenge []byte) ([]byte, error) {
				var unmarshalledChallenge common_devid.ChallengeRequest
				err := json.Unmarshal(challenge, &unmarshalledChallenge)
				require.NoError(t, err)

				devIDChallengeResponse, err := session.SolveDevIDChallenge(unmarshalledChallenge.DevID)
				require.NoError(t, err)

				credActChallengeResponse, err := session.SolveCredActivationChallenge(
					unmarshalledChallenge.CredActivation.Credential,
					unmarshalledChallenge.CredActivation.Secret)
				require.NoError(t, err)

				response, err := json.Marshal(common_devid.ChallengeResponse{
					DevID:          devIDChallengeResponse,
					CredActivation: credActChallengeResponse,
				})
				require.NoError(t, err)

				return response, nil
			}

			// Configure and run plugin
			plugin := loadPlugin(t, fmt.Sprintf(`devid_ca_path = %q, endorsement_ca_path = %q`,
				devIDBundlePath, endorsementBundlePath))

			result, err := plugin.Attest(context.Background(), payload, challengeFn)
			require.NoError(t, err)
			require.NotNil(t, result)

			require.Equal(t, tt.expectedAgentID, result.AgentID)
			requireSelectorsMatch(t, tt.expectedSelectors, result.Selectors)
		})
	}
}

func loadPlugin(t *testing.T, config string) nodeattestor.NodeAttestor {
	v1 := new(nodeattestor.V1)
	plugintest.Load(t, tpmdevid.BuiltIn(), v1,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configure(config),
	)
	return v1
}

func marshalPayload(t *testing.T, attReq *common_devid.AttestationRequest) []byte {
	attReqBytes, err := json.Marshal(attReq)
	require.NoError(t, err)
	return attReqBytes
}

func requireSelectorsMatch(t *testing.T, expected []*common.Selector, actual []*common.Selector) {
	require.Equal(t, len(expected), len(actual))
	for idx, expSel := range expected {
		require.Equal(t, expSel.Type, actual[idx].Type)
		require.Equal(t, expSel.Value, actual[idx].Value)
	}
}
