//go:build !darwin

package tpmutil_test

import (
	"crypto/x509"
	"io"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil"
	server_devid "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/tpmdevid"
	"github.com/spiffe/spire/test/tpmsimulator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// DevID identities
	devIDRSA *tpmsimulator.Credential
	devIDECC *tpmsimulator.Credential

	// TPM passwords
	tpmPasswords = tpmutil.TPMPasswords{
		EndorsementHierarchy: "endorsement-hierarchy-pass",
		OwnerHierarchy:       "owner-hierarchy-pass",
		DevIDKey:             "devid-pass",
	}
	isWindows = runtime.GOOS == "windows"
)

func setupSimulator(t *testing.T) *tpmsimulator.TPMSimulator {
	// Create a new TPM simulator
	sim, err := tpmsimulator.New(tpmPasswords.EndorsementHierarchy, tpmPasswords.OwnerHierarchy)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, sim.Close(), "failed to close the TPM simulator")
	})
	tpmutil.OpenTPM = func(s ...string) (io.ReadWriteCloser, error) {
		return sim.OpenTPM(s...)
	}

	// Create DevIDs
	provisioningCA, err := tpmsimulator.NewProvisioningCA(&tpmsimulator.ProvisioningConf{})
	require.NoError(t, err)

	devIDRSA, err = sim.GenerateDevID(
		provisioningCA,
		tpmsimulator.RSA,
		tpmPasswords.DevIDKey)
	require.NoError(t, err)

	devIDECC, err = sim.GenerateDevID(
		provisioningCA,
		tpmsimulator.ECC,
		tpmPasswords.DevIDKey)
	require.NoError(t, err)

	return sim
}

func TestNewSession(t *testing.T) {
	sim := setupSimulator(t)

	tests := []struct {
		name          string
		expErr        string
		expWindowsErr string
		scfg          *tpmutil.SessionConfig
		hook          func(*testing.T, *tpmsimulator.TPMSimulator) io.Closer
	}{
		{
			name:   "NewSession fails if logger is not provided",
			expErr: `missing logger`,
			scfg:   &tpmutil.SessionConfig{},
		},
		// TODO: windows is not allowing to set a path, so what must we do here?
		{
			name:          "NewSession fails if a wrong device path is provided",
			expErr:        `cannot open TPM at "": unexpected TPM device path "" (expected "/dev/tpmrm0")`,
			expWindowsErr: "cannot load DevID key on TPM: tpm2.DecodePublic failed: decoding TPMT_PUBLIC: EOF",
			scfg: &tpmutil.SessionConfig{
				Log: hclog.NewNullLogger(),
			},
		},
		{
			name:   "NewSesion fails if DevID blobs cannot be loaded",
			expErr: "cannot load DevID key on TPM: tpm2.DecodePublic failed: decoding TPMT_PUBLIC: unexpected EOF",
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
				Passwords:  tpmPasswords,
			},
		},
		{
			name:   "NewSesion fails if owner hierarchy password is not correct",
			expErr: "cannot load DevID key on TPM: tpm2.CreatePrimaryEx failed: session 1, error code 0x22 : authorization failure without DA implications",
			scfg: &tpmutil.SessionConfig{
				DevicePath: "/dev/tpmrm0",
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				Log:        hclog.NewNullLogger(),
				Passwords: func() tpmutil.TPMPasswords {
					passwordsCopy := tpmPasswords
					passwordsCopy.OwnerHierarchy = "wrong-password"
					return passwordsCopy
				}(),
			},
		},
		{
			name:   "NewSesion fails if endorsement hierarchy password is not correct",
			expErr: "cannot create endorsement key: session 1, error code 0x22 : authorization failure without DA implications",
			scfg: &tpmutil.SessionConfig{
				DevicePath: "/dev/tpmrm0",
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				Log:        hclog.NewNullLogger(),
				Passwords: func() tpmutil.TPMPasswords {
					passwordsCopy := tpmPasswords
					passwordsCopy.EndorsementHierarchy = "wrong-password"
					return passwordsCopy
				}(),
			},
		},
		{
			name: "NewSession succeeds",
			scfg: &tpmutil.SessionConfig{
				DevicePath: "/dev/tpmrm0",
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				Log:        hclog.NewNullLogger(),
				Passwords:  tpmPasswords,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run hook if exists, generally used to intentionally cause an error
			// and test more code paths.
			if tt.hook != nil {
				closer := tt.hook(t, sim)
				defer closer.Close()
			}

			if isWindows {
				tt.scfg.DevicePath = ""
			}

			tpm, err := tpmutil.NewSession(tt.scfg)
			if tt.expErr != "" {
				expectErr := tt.expErr
				if isWindows && tt.expWindowsErr != "" {
					expectErr = tt.expWindowsErr
				}

				require.EqualError(t, err, expectErr)
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
				Passwords:  tpmPasswords,
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
				Passwords:  tpmPasswords,
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
				Passwords:  tpmPasswords,
			},
		},
		{
			name:   "SolveDevIDChallenge fails if DevID key password is not correct",
			nonce:  []byte("nonce"),
			expErr: "failed to sign nonce: tpm2.Sign failed: session 1, error code 0xe : the authorization HMAC check failed and DA counter incremented",
			devID:  devIDRSA.Certificate,
			scfg: &tpmutil.SessionConfig{
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				DevicePath: "/dev/tpmrm0",
				Log:        hclog.NewNullLogger(),
				Passwords: func() tpmutil.TPMPasswords {
					passwordsCopy := tpmPasswords
					passwordsCopy.DevIDKey = "wrong-password"
					return passwordsCopy
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isWindows {
				tt.scfg.DevicePath = ""
			}
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

	var devicePath string
	if !isWindows {
		devicePath = "/dev/tpmrm0"
	}
	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: devicePath,
		Log:        hclog.NewNullLogger(),
		Passwords:  tpmPasswords,
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

	tests := []struct {
		name      string
		expErr    string
		passwords tpmutil.TPMPasswords
	}{
		{
			name:      "CertifyDevIDKey succeeds",
			passwords: tpmPasswords,
		},
		{
			name:   "CertifyDevIDKey fails if DevID key password is not correct",
			expErr: "tpm2.Certify failed: session 1, error code 0xe : the authorization HMAC check failed and DA counter incremented",
			passwords: func() tpmutil.TPMPasswords {
				passwordsCopy := tpmPasswords
				passwordsCopy.DevIDKey = "wrong-password"
				return passwordsCopy
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var devicePath string
			if !isWindows {
				devicePath = "/dev/tpmrm0"
			}

			tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
				DevIDPriv:  devIDRSA.PrivateBlob,
				DevIDPub:   devIDRSA.PublicBlob,
				DevicePath: devicePath,
				Log:        hclog.NewNullLogger(),
				Passwords:  tt.passwords,
			})
			require.NoError(t, err)
			defer tpm.Close()

			akPubBytes := tpm.GetAKPublic()
			akPub, err := tpm2.DecodePublic(akPubBytes)
			require.NoError(t, err)

			devIDPub, err := tpm2.DecodePublic(devIDRSA.PublicBlob)
			require.NoError(t, err)

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
	sim := setupSimulator(t)

	var devicePath string
	if !isWindows {
		devicePath = "/dev/tpmrm0"
	}

	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: devicePath,
		Log:        hclog.NewNullLogger(),
		Passwords:  tpmPasswords,
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
			name: "GetEKCert succeeds if there is trailing data after the certificate in the TPM NV index",
			hook: func() {
				ekCertBytes, err := tpm.GetEKCert()
				require.NoError(t, err)

				trailingData := []byte("trailing data")
				err = sim.SetEndorsementCertificate(append(ekCertBytes, trailingData...))
				require.NoError(t, err)
			},
		},
		{
			name:   "GetEKCert fails if TPM has not a EK Cert loaded in default handle",
			expErr: "failed to read NV index 01c00002: decoding NV_ReadPublic response: handle 1, error code 0xb : the handle is not correct for the use",
			hook: func() {
				err := tpm2.NVUndefineSpace(sim, "", tpm2.HandlePlatform, tpmutil.EKCertificateHandleRSA)
				require.NoError(t, err)
			},
		},
		{
			name:   "GetEKCert fails if the EK Cert loaded in default handle is not parseable",
			expErr: "failed to unmarshall certificate read from 01c00002: asn1: syntax error: data truncated",
			hook: func() {
				err := sim.SetEndorsementCertificate([]byte("not an endorsement certificate"))
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
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

			parsedEKCert, err := x509.ParseCertificate(ekCert)
			require.NoError(t, err)
			require.NotNil(t, parsedEKCert)
		})
	}
}

func TestGetEKPublic(t *testing.T) {
	sim := setupSimulator(t)

	var devicePath string
	if !isWindows {
		devicePath = "/dev/tpmrm0"
	}

	tpm, err := tpmutil.NewSession(&tpmutil.SessionConfig{
		DevIDPriv:  devIDRSA.PrivateBlob,
		DevIDPub:   devIDRSA.PublicBlob,
		DevicePath: devicePath,
		Log:        hclog.NewNullLogger(),
		Passwords:  tpmPasswords,
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
			expErr: "cannot read EK from handle: warning code 0x10 : the 1st handle in the handle area references a transient object or session that is not loaded",
			hook: func() {
				require.NoError(t, sim.ManufactureReset())
			},
		},
	}

	for _, tt := range tests {
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
		expWindowsErr    string
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
			expErr:      "not found",
			deviceNames: []string{"not-a-tpm-device-1", "not-a-tpm-device-2"},
		},
		{
			name:        "AutoDetectTPMPath fails to detect TPM if more than one 'tpmrmX' like device is found",
			baseTPMDir:  t.TempDir(),
			expErr:      "more than one possible TPM device was found",
			deviceNames: []string{"not-a-tpm-device-1", "tpmrm0", "not-a-tpm-device-2", "tpmrm1"},
		},
		{
			name:        "AutoDetectTPMPath fails to detect TPM if more than one 'tpmX' like device is found",
			baseTPMDir:  t.TempDir(),
			expErr:      "more than one possible TPM device was found",
			deviceNames: []string{"not-a-tpm-device-1", "tpm0", "not-a-tpm-device-2", "tpm1"},
		},
		{
			name:          "AutoDetectTPMPath fails to detect TPM if TPM base directory cannot be read",
			baseTPMDir:    "non-existent-dir",
			expErr:        "open non-existent-dir: no such file or directory",
			expWindowsErr: "open non-existent-dir: The system cannot find the file specified.",
			deviceNames:   []string{"tpm0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create devices
			for _, fileName := range tt.deviceNames {
				_ = os.WriteFile(path.Join(tt.baseTPMDir, fileName), []byte("content"), os.ModeDevice)
			}

			expectedPath := path.Join(tt.baseTPMDir, tt.targetDeviceName)
			detectedPath, err := tpmutil.AutoDetectTPMPath(tt.baseTPMDir)
			if tt.expErr != "" {
				expectErr := tt.expErr
				if runtime.GOOS == "windows" && tt.expWindowsErr != "" {
					expectErr = tt.expWindowsErr
				}
				require.EqualError(t, err, expectErr)
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

// createTPMKey creates a key on the simulated TPM. It returns an io.Closer to
// flush the key once it is no more required.
// This function is used to out-of-memory the TPM in unit tests.
func createTPMKey(t *testing.T, sim *tpmsimulator.TPMSimulator) io.Closer {
	srk, err := client.NewKey(sim, tpm2.HandlePlatform, client.DefaultEKTemplateRSA())
	require.NoError(t, err)
	return keyCloser(srk.Close)
}
