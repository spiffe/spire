// +build linux

package tpmutil_test

import (
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	server_devid "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/require"
)

// simData holds TPM simulator data.
var sim *tpmsimulator.TPMSimulator
var devIDRSA *tpmsimulator.Credential
var devIDECC *tpmsimulator.Credential

// OpenSimulatedTPM works in the same way than tpmutil.OpenTPM() but it ignores
// the path argument and opens a connection to a simulated TPM.
func openSimulatedTPM(tpmPath string) (io.ReadWriteCloser, error) {
	if tpmPath == "" {
		return nil, errors.New("empty path")
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

	devIDRSA, err = sim.GenerateDevID(provisioningCA, tpmsimulator.RSA)
	require.NoError(t, err)

	devIDECC, err = sim.GenerateDevID(provisioningCA, tpmsimulator.ECC)
	require.NoError(t, err)
}

func teardownSimulator(t *testing.T) {
	require.NoError(t, sim.Close())
}

func TestNewSession(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tests := []struct {
		name   string
		expErr string
		scfg   *tpmutil.SessionConfig
		hook   func(*testing.T) io.Closer
	}{
		{
			name:   "NewSession fails if logger is not provided",
			expErr: `missing logger`,
			scfg:   &tpmutil.SessionConfig{},
		},
		{
			name:   "NewSession fails if a wrong device path is provided",
			expErr: `cannot open TPM at "": empty path`,
			scfg: &tpmutil.SessionConfig{
				Log: hclog.NewNullLogger(),
			},
		},
		{
			name:   "NewSesion fails if DevID blobs cannot be loaded",
			expErr: "cannot load DevID: failed to load key on TPM: tpm2.Public decoding failed: decoding TPMT_PUBLIC: unexpected EOF",
			scfg: &tpmutil.SessionConfig{
				DevicePath: "/dev/tpmrm0",
				DevIDPriv:  []byte("not a private key blob"),
				DevIDPub:   []byte("not a public key blob"),
				Log:        hclog.NewNullLogger(),
			},
		},
		{
			name:   "NewSesion fails if AK cannot be created",
			expErr: "cannot create attestation key: failed to create AK: warning code 0x2 : out of memory for object contexts",
			hook:   createTPMKey,
			scfg: &tpmutil.SessionConfig{
				DevicePath: "/dev/tpmrm0",
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				Log:        hclog.NewNullLogger(),
			},
		},
		{
			name: "NewSession succeeds",
			scfg: &tpmutil.SessionConfig{
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				DevicePath: "/dev/tpmrm0",
				Log:        hclog.NewNullLogger(),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Run hook if exist, generally used to intentionally cause an error
			// and test more code paths.
			if tt.hook != nil {
				closer := tt.hook(t)
				defer closer.Close()
			}

			tpm, err := tpmutil.NewSession(tt.scfg)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, tpm)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tpm)
		})
	}
}

func TestSolveDevIDChallenge(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tests := []struct {
		name   string
		expErr string
		nonce  []byte
		devID  *x509.Certificate
		scfg   *tpmutil.SessionConfig
	}{
		{
			name:  "SolveDevIDChallenge succeeds for RSA",
			nonce: []byte("nonce"),
			devID: devIDRSA.Certificate,
			scfg: &tpmutil.SessionConfig{
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				DevicePath: "/dev/tpmrm0",
				Log:        hclog.NewNullLogger(),
			},
		},
		{
			name:  "SolveDevIDChallenge succeeds for ECC",
			nonce: []byte("nonce"),
			devID: devIDECC.Certificate,
			scfg: &tpmutil.SessionConfig{
				DevIDPriv:  devIDECC.PrivateBlob,
				DevIDPub:   devIDECC.PublicBlob,
				DevicePath: "/dev/tpmrm0",
				Log:        hclog.NewNullLogger(),
			},
		},
		{
			name:   "SolveDevIDChallenge fails if nonce is bigger than 1024 bytes",
			nonce:  make([]byte, 1025),
			expErr: "failed to sign nonce: tpm2.Hash failed: parameter 1, error code 0x15 : structure is the wrong size",
			devID:  devIDRSA.Certificate,
			scfg: &tpmutil.SessionConfig{
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				DevicePath: "/dev/tpmrm0",
				Log:        hclog.NewNullLogger(),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tpm, err := tpmutil.NewSession(tt.scfg)
			require.NoError(t, err)
			defer tpm.Close()

			signedNonce, err := tpm.SolveDevIDChallenge(tt.nonce)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, signedNonce)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, signedNonce)

			err = server_devid.VerifyDevIDChallenge(tt.devID, tt.nonce, signedNonce)
			require.NoError(t, err)
		})
	}
}

func TestSolveCredActivationChallenge(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: "/dev/tpmrm0",
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)
	defer tpm.Close()

	ekPubBytes, err := tpm.GetEKPublic()
	require.NoError(t, err)
	ekPub, err := tpm2.DecodePublic(ekPubBytes)
	require.NoError(t, err)

	akPubBytes := tpm.GetAKPublic()
	akPub, err := tpm2.DecodePublic(akPubBytes)
	require.NoError(t, err)

	challenge, expectedNonce, err := server_devid.NewCredActivationChallenge(akPub, ekPub)
	require.NoError(t, err)

	tests := []struct {
		name            string
		expErr          string
		credBlob        []byte
		encryptedSecret []byte
	}{
		{
			name:            "SolveCredActivationChallenge succeeds",
			credBlob:        challenge.Credential,
			encryptedSecret: challenge.Secret,
		},
		{
			name:            "SolveCredActivationChallenge fails if tpm2.ActivateCredential fails",
			expErr:          "failed to activate credential: parameter 2, error code 0x15 : structure is the wrong size",
			credBlob:        []byte("wrong cred"),
			encryptedSecret: []byte("wrong secret"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			nonce, err := tpm.SolveCredActivationChallenge(tt.credBlob, tt.encryptedSecret)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, nonce)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, nonce)
			require.NoError(t, server_devid.VerifyCredActivationChallenge(expectedNonce, nonce))
		})
	}
}

func TestCertifyDevIDKey(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: "/dev/tpmrm0",
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)
	defer tpm.Close()

	akPubBytes := tpm.GetAKPublic()
	akPub, err := tpm2.DecodePublic(akPubBytes)
	require.NoError(t, err)

	devIDPub, err := tpm2.DecodePublic(devIDRSA.PublicBlob)
	require.NoError(t, err)

	tests := []struct {
		name   string
		expErr string
		hook   func()
	}{
		{
			name: "CertifyDevIDKey succeeds",
		},
		{
			name:   "CertifyDevIDKey fails if tpm2.Certify fails",
			expErr: "certify failed: warning code 0x10 : the 1st handle in the handle area references a transient object or session that is not loaded",
			hook:   func() { sim.ManufactureReset() },
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.hook != nil {
				tt.hook()
			}

			attData, signature, err := tpm.CertifyDevIDKey()
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, attData)
				require.Nil(t, signature)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, attData)
			require.NotNil(t, signature)

			err = server_devid.VerifyDevIDCertification(&akPub, &devIDPub, attData, signature)
			require.NoError(t, err)
		})
	}
}

func TestGetEKCert(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: "/dev/tpmrm0",
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)
	defer tpm.Close()

	tests := []struct {
		name   string
		expErr string
		hook   func()
	}{
		{
			name: "GetEKCert succeeds",
		},
		{
			name:   "GetEKCert fails if tpm has not a EK Cert loaded in default handle",
			expErr: "failed to read NV index 01c00002: decoding NV_ReadPublic response: handle 1, error code 0xb : the handle is not correct for the use",
			hook: func() {
				require.NoError(t, tpm2.NVUndefineSpace(sim, "", tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA))
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.hook != nil {
				tt.hook()
			}

			ekCert, err := tpm.GetEKCert()
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, ekCert)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ekCert)
		})
	}
}

func TestGetEKPublic(t *testing.T) {
	setupSimulator(t)
	defer teardownSimulator(t)

	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: "/dev/tpmrm0",
		Log:        hclog.NewNullLogger(),
	})
	require.NoError(t, err)
	defer tpm.Close()

	tests := []struct {
		name   string
		expErr string
		hook   func()
	}{
		{
			name: "GetEKPublic succeeds",
		},
		{
			name:   "GetEKPublic fails if tpm has not a EK public key loaded",
			expErr: "cannot read EK from handle: handle 1, error code 0xb : the handle is not correct for the use",
			hook: func() {
				require.NoError(t, sim.ManufactureReset())
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.hook != nil {
				tt.hook()
			}

			ekPub, err := tpm.GetEKPublic()
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Nil(t, ekPub)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ekPub)
		})
	}
}

func TestAutoDetectTPMPath(t *testing.T) {

	tests := []struct {
		name             string
		baseTPMDir       string
		deviceNames      []string
		targetDeviceName string
		expErr           string
	}{
		{
			name:             "AutoDetectTPMPath succeeds for 'tpmrmX' device names",
			baseTPMDir:       t.TempDir(),
			targetDeviceName: "tpmrm0",
			deviceNames:      []string{"not-a-tpm-device-1", "tpmrm0", "not-a-tpm-device-2"},
		},
		{
			name:             "AutoDetectTPMPath succeeds for 'tpmX' device names",
			baseTPMDir:       t.TempDir(),
			targetDeviceName: "tpm0",
			deviceNames:      []string{"not-a-tpm-device-1", "tpm0", "not-a-tpm-device-2"},
		},
		{
			name:             "AutoDetectTPMPath prefers 'tpmrmX' device name to 'tpmX' ",
			baseTPMDir:       t.TempDir(),
			targetDeviceName: "tpmrm2",
			deviceNames:      []string{"tpm0", "tpm1", "tpmrm2"},
		},
		{
			name:        "AutoDetectTPMPath fails to detect TPM if there are no devices that match the name pattern",
			baseTPMDir:  t.TempDir(),
			expErr:      "unable to autodetect TPM",
			deviceNames: []string{"not-a-tpm-device-1", "not-a-tpm-device-2"},
		},
		{
			name:        "AutoDetectTPMPath fails to detect TPM if device is not a TPM 2.0 device",
			baseTPMDir:  t.TempDir(),
			expErr:      "unable to autodetect TPM",
			deviceNames: []string{"tpm0"},
		},
		{
			name:        "AutoDetectTPMPath fails to detect TPM if TPM base directory cannot be read",
			baseTPMDir:  "non-existent-dir",
			expErr:      "open non-existent-dir: no such file or directory",
			deviceNames: []string{"tpm0"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create devices
			for _, fileName := range tt.deviceNames {
				_ = ioutil.WriteFile(path.Join(tt.baseTPMDir, fileName), []byte("content"), os.ModeDevice)
			}

			// Override OpenTPM() function to return a TPM simulator on targetDevice path
			expectedPath := path.Join(tt.baseTPMDir, tt.targetDeviceName)
			tpmutil.OpenTPM = func(path string) (io.ReadWriteCloser, error) {
				if path == expectedPath {
					return tpmsimulator.New()
				}
				return nil, errors.New("not a TPM device")
			}

			detectedPath, err := tpmutil.AutoDetectTPMPath(tt.baseTPMDir)
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				require.Empty(t, detectedPath)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, detectedPath)
			require.Equal(t, expectedPath, detectedPath)
		})
	}
}

type keyCloser func()

func (f keyCloser) Close() error {
	f()
	return nil
}

// createTPMKey creates a key on the simulated TPM. It returns a io.Closer to
// flush the key once it is no more required.
// This function is used to out-of-memory the TPM in unit tests.
func createTPMKey(t *testing.T) io.Closer {
	srk, err := tpm2tools.NewKey(sim, tpm2.HandleOwner, tpmutil.SRKTemplateHighRSA())
	require.NoError(t, err)
	return keyCloser(srk.Close)
}
