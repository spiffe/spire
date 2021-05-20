package tpmutil

import (
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/hashicorp/go-hclog"
)

// ekRSACertificateHandle is the default handle for RSA endorsement key according
// to the TCG TPM v2.0 Provisioning Guidance, section 7.8
// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
const EKCertificateHandleRSA = tpmutil.Handle(0x01c00002)

// Session represents a TPM with loaded DevID credentials and exposes methods
// to perfom cryptographyc operations relevant to the SPIRE node attestation
// workflow.
type Session struct {
	devID *SigningKey
	ak    *SigningKey
	ek    *tpm2tools.Key

	akPub []byte

	rwc io.ReadWriteCloser
	log hclog.Logger
}

type SessionConfig struct {
	DevicePath string

	DevIDPriv []byte
	DevIDPub  []byte

	Log hclog.Logger
}

var OpenTPM func(string) (io.ReadWriteCloser, error) = tpm2.OpenTPM

// NewSession opens a connection to a TPM and configures it to be used for
// node attestation.
func NewSession(scfg *SessionConfig) (*Session, error) {
	if scfg.Log == nil {
		return nil, errors.New("missing logger")
	}

	// Open TPM connection
	rwc, err := OpenTPM(scfg.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM at %q: %w", scfg.DevicePath, err)
	}

	// Create session
	tpm := &Session{
		rwc: rwc,
		log: scfg.Log,
	}

	// Close session in case of error
	defer func() {
		if err != nil {
			tpm.Close()
		}
	}()

	// Load DevID
	tpm.devID, err = tpm.loadKey(scfg.DevIDPub, scfg.DevIDPriv)
	if err != nil {
		return nil, fmt.Errorf("cannot load DevID: %w", err)
	}

	// Create Attestation Key
	akPriv, akPub, err := tpm.createAttestationKey()
	if err != nil {
		return nil, fmt.Errorf("cannot create attestation key: %w", err)
	}
	tpm.akPub = akPub

	// Load Attestation Key
	tpm.ak, err = tpm.loadKey(akPub, akPriv)
	if err != nil {
		return nil, fmt.Errorf("cannot load attestation key: %w", err)
	}

	// Regenerate Endorsement Key using the default RSA template
	tpm.ek, err = tpm2tools.EndorsementKeyRSA(tpm.rwc)
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement key: %w", err)
	}

	return tpm, nil
}

// Close unloads TPM loaded objects and close the connection to the TPM.
func (c *Session) Close() {
	if c.devID != nil {
		err := c.devID.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close DevID handle: %v", err))
		}
	}

	if c.ak != nil {
		err := c.ak.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close attestation key handle: %v", err))
		}
	}

	if c.ek != nil {
		c.ek.Close()
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
func (c *Session) SolveDevIDChallenge(nonce []byte) ([]byte, error) {
	signedNonce, err := c.devID.Sign(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to sign nonce: %w", err)
	}

	return signedNonce, nil
}

// SolveCredActivationChallenge runs credential activation on the TPM. It proves
// that the attestation key resides on the same TPM as the endorsement key.
func (c *Session) SolveCredActivationChallenge(credentialBlob, secret []byte) ([]byte, error) {
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
		c.ak.Handle,
		c.ek.Handle(),
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

// CertifyDevIDKey proves that the DevID Key is in the same TPM than
// Attestation Key.
func (c *Session) CertifyDevIDKey() ([]byte, []byte, error) {
	return c.ak.Certify(c.devID.Handle)
}

// GetEKCert returns TPM endorsement certificate.
func (c *Session) GetEKCert() ([]byte, error) {
	EKCert, err := tpm2.NVRead(c.rwc, EKCertificateHandleRSA)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV index %08x: %w", EKCertificateHandleRSA, err)
	}

	return EKCert, nil
}

// GetEKPublic returns the public part of the Endorsement Key encoded in
// TPM wire format.
func (c *Session) GetEKPublic() ([]byte, error) {
	publicEK, _, _, err := tpm2.ReadPublic(c.rwc, c.ek.Handle())
	if err != nil {
		return nil, fmt.Errorf("cannot read EK from handle: %w", err)
	}

	encodedPublicEK, err := publicEK.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	return encodedPublicEK, nil
}

// GetAKPublic returns the public part of the attestation key encoded in
// TPM wire format.
func (c *Session) GetAKPublic() []byte {
	return c.akPub
}

// loadKey loads a key pair into the TPM.
func (c *Session) loadKey(pub, priv []byte) (*SigningKey, error) {
	sk, err := LoadSigningKey(c.rwc, pub, priv, c.log)
	if err != nil {
		return nil, fmt.Errorf("failed to load key on TPM: %w", err)
	}
	return sk, nil
}

func (c *Session) createAttestationKey() ([]byte, []byte, error) {
	srk, err := tpm2tools.NewKey(c.rwc, tpm2.HandleOwner, SRKTemplateHighRSA())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SRK: %w", err)
	}
	defer srk.Close()

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(
		c.rwc,
		srk.Handle(),
		tpm2.PCRSelection{},
		"",
		"",
		tpm2tools.AIKTemplateRSA(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AK: %w", err)
	}

	return privBlob, pubBlob, nil
}

func (c *Session) createPolicySession() (tpmutil.Handle, error) {
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

func (c *Session) flushContext(handle tpmutil.Handle) {
	err := tpm2.FlushContext(c.rwc, handle)
	if err != nil {
		c.log.Warn(fmt.Sprintf("Failed to flush handle %v: %v", handle, err))
	}
}
