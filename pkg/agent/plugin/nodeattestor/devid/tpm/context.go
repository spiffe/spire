package tpm

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/hashicorp/go-hclog"
)

// EKRSACertificateHandle is the default handle for RSA endorsement key according
// to the TCG TPM v2.0 Provisioning Guidance, section 7.8
// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
const ekRSACertificateHandle = tpmutil.Handle(0x01c00002)

// Context represent a TPM context and exposes functions to operate the TPM.
type Context struct {
	DevID *SigningKey
	AK    *SigningKey
	EK    *tpm2tools.Key

	EKPub  []byte
	EKCert []byte

	CertifiedDevID         []byte
	CertificationSignature []byte

	rwc io.ReadWriteCloser
	log hclog.Logger
}

// Open opens a new connection to a TPM. Path could be the path to a device
// or to an unix domain socket. The returned TPM context must be closed when it
// is no longer used.
func Open(path string, log hclog.Logger) (*Context, error) {
	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, err
	}

	return &Context{
		rwc: rwc,
		log: log,
	}, nil
}

// Close unloads TPM loaded objects and close the connection to the TPM.
func (c *Context) Close() {
	if c.DevID != nil {
		err := c.DevID.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close DevID handle: %v", err))
		}
	}

	if c.AK != nil {
		err := c.AK.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close attestation key handle: %v", err))
		}
	}

	if c.EK != nil {
		c.EK.Close()
	}

	if c.rwc != nil {
		// EmulatorReadWriteCloser type does not need to be closed. It closes
		// the connection after each Read() call. Closing it again results in
		// an error.
		_, ok := c.rwc.(*tpmutil.EmulatorReadWriteCloser)
		if ok {
			return
		}

		err := c.rwc.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close TPM: %v", err))
		}
	}
}

// SolveDevIDChallenge request the TPM to sign the provided nonce using the loaded
// DevID credentials.
func (c *Context) SolveDevIDChallenge(nonce []byte) ([]byte, error) {
	return c.DevID.Sign(nonce)
}

// SolveCredActivationChallenge runs credential activation on the TPM. It proves
// that the attestation key resides on the same TPM as the endorsement key.
func (c *Context) SolveCredActivationChallenge(credentialBlob, secret []byte) ([]byte, error) {
	hSession, err := c.createPolicySession()
	if err != nil {
		return nil, err
	}

	b, err := tpm2.ActivateCredentialUsingAuth(
		c.rwc,
		[]tpm2.AuthCommand{
			{Session: tpm2.HandlePasswordSession},
			{Session: hSession},
		},
		c.AK.Handle,
		c.EK.Handle(),
		credentialBlob,
		secret,
	)
	if err != nil {
		// Flush only in case of error. If the command executes successfully it
		// closes the session. Closing it again produces an error.
		c.flushContext(hSession)
		return b, fmt.Errorf("failed to activate credential: %w", err)
	}

	return b, nil
}

// LoadKey loads a key pair into the TPM.
func (c *Context) LoadKey(pub, priv []byte) (*SigningKey, error) {
	sk, err := LoadSigningKey(c.rwc, pub, priv, c.log)
	if err != nil {
		return nil, fmt.Errorf("failed to load key on TPM: %w", err)
	}
	return sk, nil
}

// GetEKCert returns TPM endorsement certificate.
func (c *Context) GetEKCert() ([]byte, error) {
	EKCert, err := tpm2.NVRead(c.rwc, ekRSACertificateHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV index %08x: %w", ekRSACertificateHandle, err)
	}

	return EKCert, nil
}

// RegenerateEK regenerates the Endorsement Key using the default RSA template
func (c *Context) RegenerateEK() (*tpm2tools.Key, error) {
	return tpm2tools.EndorsementKeyRSA(c.rwc)
}

// EncodePublicEK returns the public part of the Endorsement Key encoded in
// TPM wire format
func (c *Context) EncodePublicEK() ([]byte, error) {
	publicEK, _, _, err := tpm2.ReadPublic(c.rwc, c.EK.Handle())
	if err != nil {
		return nil, fmt.Errorf("cannot read EK from handle: %w", err)
	}

	encodedPublicEK, err := publicEK.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	return encodedPublicEK, nil
}

func (c *Context) createPolicySession() (tpmutil.Handle, error) {
	var nonceCaller [32]byte
	hSession, _, err := tpm2.StartAuthSession(
		c.rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		nonceCaller[:],
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		return 0, err
	}

	_, err = tpm2.PolicySecret(
		c.rwc,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession},
		hSession,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		c.flushContext(hSession)
		return 0, err
	}

	return hSession, nil
}

func (c *Context) flushContext(handle tpmutil.Handle) {
	err := tpm2.FlushContext(c.rwc, handle)
	if err != nil {
		c.log.Warn(fmt.Sprintf("Failed to flush handle %v: %v", handle, err))
	}
}
