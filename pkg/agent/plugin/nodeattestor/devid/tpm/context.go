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

	EKPub    []byte
	EKCert   []byte
	EKHandle tpmutil.Handle

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

	if c.rwc != nil {
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
	hSession, err := c.createPolicySession(c.rwc)
	if err != nil {
		return nil, err
	}
	defer c.flushContext(c.rwc, hSession)

	b, err := tpm2.ActivateCredentialUsingAuth(
		c.rwc,
		[]tpm2.AuthCommand{
			{Session: tpm2.HandlePasswordSession},
			{Session: hSession},
		},
		c.AK.Handle,
		c.EKHandle,
		credentialBlob,
		secret,
	)
	if err != nil {
		return b, fmt.Errorf("failed to activate credential: %w", err)
	}

	return b, nil
}

// LoadKey loads a key pair into the TPM.
func (c *Context) LoadKey(pub, priv []byte) (*SigningKey, error) {
	sk, err := LoadSigningKey(c.rwc, pub, priv)
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

// CreateEK creates an Endorsement Key using the default RSA template
func (c *Context) CreateEK() ([]byte, tpmutil.Handle, error) {
	return c.newCachedKey(
		c.rwc,
		tpm2tools.DefaultEKTemplateRSA(),
		tpm2.HandleOwner,
		tpm2.HandleEndorsement,
		tpm2tools.EKReservedHandle,
	)
}

func (c *Context) newCachedKey(rw io.ReadWriter, template tpm2.Public, owner, parent, cachedHandle tpmutil.Handle) ([]byte, tpmutil.Handle, error) {
	cachedPub, _, _, err := tpm2.ReadPublic(rw, cachedHandle)
	if err == nil {
		if cachedPub.MatchesTemplate(template) {
			cachedPubData, err := cachedPub.Encode()
			if err != nil {
				return nil, 0, err
			}

			return cachedPubData, cachedHandle, nil
		}

		// Kick out old cached key if it does not match
		err = tpm2.EvictControl(rw, "", owner, cachedHandle, cachedHandle)
		if err != nil {
			return nil, 0, err
		}
	}

	pubData, handle, err := createPrimaryKey(rw, parent, template)
	if err != nil {
		return nil, 0, err
	}

	// Flush the current handler (handle) since the object will be
	// persisted at cachedHandler.
	defer c.flushContext(rw, handle)

	err = tpm2.EvictControl(rw, "", owner, handle, cachedHandle)
	if err != nil {
		return nil, 0, err
	}

	return pubData, cachedHandle, nil
}

func (c *Context) createPolicySession(rw io.ReadWriter) (tpmutil.Handle, error) {
	var nonceCaller [32]byte
	hSession, _, err := tpm2.StartAuthSession(
		rw,
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
		rw,
		tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession},
		hSession,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		c.flushContext(rw, hSession)
		return 0, err
	}

	return hSession, nil
}

func (c *Context) flushContext(rw io.ReadWriter, handle tpmutil.Handle) {
	err := tpm2.FlushContext(rw, handle)
	if err != nil {
		c.log.Warn(fmt.Sprintf("Failed to flush handle %v: %v", handle, err))
	}
}

func createPrimaryKey(rw io.ReadWriter, owner tpmutil.Handle, template tpm2.Public) ([]byte, tpmutil.Handle, error) {
	handle, pubBlob, _, _, _, _, err := tpm2.CreatePrimaryEx(
		rw,
		owner,
		tpm2.PCRSelection{},
		"",
		"",
		template,
	)
	if err != nil {
		err = fmt.Errorf("failed to create primary key: %w", err)
		return nil, 0, err
	}

	return pubBlob, handle, nil
}
