package tpmutil

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
)

// ekRSACertificateHandle is the default handle for RSA endorsement key according
// to the TCG TPM v2.0 Provisioning Guidance, section 7.8
// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
const EKCertificateHandleRSA = tpmutil.Handle(0x01c00002)

// randomPasswordSize is the number of bytes of generated random passwords
const randomPasswordSize = 32

// Session represents a TPM with loaded DevID credentials and exposes methods
// to perfom cryptographyc operations relevant to the SPIRE node attestation
// workflow.
type Session struct {
	devID    *SigningKey
	ak       *SigningKey
	ekHandle tpmutil.Handle
	ekPub    []byte
	akPub    []byte

	endorsementHierarchyPassword string
	ownerHierarchyPassword       string

	rwc io.ReadWriteCloser
	log hclog.Logger
}

type TPMPasswords struct {
	EndorsementHierarchy string
	OwnerHierarchy       string
	DevIDKey             string
}

type SessionConfig struct {
	// in future iterations of tpm libraries, TPM will accept a
	// list of device paths (https://github.com/google/go-tpm/pull/256)
	DevicePath string
	DevIDPriv  []byte
	DevIDPub   []byte
	Passwords  TPMPasswords
	Log        hclog.Logger
}

var OpenTPM = openTPM

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
		rwc:                          rwc,
		log:                          scfg.Log,
		endorsementHierarchyPassword: scfg.Passwords.EndorsementHierarchy,
		ownerHierarchyPassword:       scfg.Passwords.OwnerHierarchy,
	}

	// Close session in case of error
	defer func() {
		if err != nil {
			tpm.Close()
		}
	}()

	// Create SRK password
	srkPassword, err := newRandomPassword()
	if err != nil {
		return nil, fmt.Errorf("cannot generate random password for storage root key: %w", err)
	}

	// Load DevID
	tpm.devID, err = tpm.loadKey(
		scfg.DevIDPub,
		scfg.DevIDPriv,
		srkPassword,
		scfg.Passwords.DevIDKey)
	if err != nil {
		return nil, fmt.Errorf("cannot load DevID key on TPM: %w", err)
	}

	// Create Attestation Key
	akPassword, err := newRandomPassword()
	if err != nil {
		return nil, fmt.Errorf("cannot generate random password for attesation key: %w", err)
	}
	akPriv, akPub, err := tpm.createAttestationKey(srkPassword, akPassword)
	if err != nil {
		return nil, fmt.Errorf("cannot create attestation key: %w", err)
	}
	tpm.akPub = akPub

	// Load Attestation Key
	tpm.ak, err = tpm.loadKey(
		akPub,
		akPriv,
		srkPassword,
		akPassword)
	if err != nil {
		return nil, fmt.Errorf("cannot load attestation key: %w", err)
	}

	// Regenerate Endorsement Key using the default RSA template
	tpm.ekHandle, tpm.ekPub, _, _, _, _, err =
		tpm2.CreatePrimaryEx(rwc, tpm2.HandleEndorsement,
			tpm2.PCRSelection{},
			scfg.Passwords.EndorsementHierarchy,
			"",
			client.DefaultEKTemplateRSA())
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement key: %w", err)
	}

	return tpm, nil
}

// Close unloads TPM loaded objects and closes the connection to the TPM.
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

	if c.ekHandle != 0 {
		c.flushContext(c.ekHandle)
	}

	if c.rwc != nil {
		if closeTPM(c.rwc) {
			return
		}

		err := c.rwc.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close TPM: %v", err))
		}
	}
}

// SolveDevIDChallenge requests the TPM to sign the provided nonce using the loaded
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
	hSession, err := c.createPolicySessionForEK()
	if err != nil {
		return nil, err
	}

	b, err := tpm2.ActivateCredentialUsingAuth(
		c.rwc,
		[]tpm2.AuthCommand{
			{Session: tpm2.HandlePasswordSession, Auth: []byte(c.ak.password)},
			{Session: hSession},
		},
		c.ak.Handle,
		c.ekHandle,
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
	return c.ak.Certify(c.devID.Handle, c.devID.password)
}

// GetEKCert returns TPM endorsement certificate.
func (c *Session) GetEKCert() ([]byte, error) {
	ekCertAndTrailingBytes, err := tpm2.NVRead(c.rwc, EKCertificateHandleRSA)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV index %08x: %w", EKCertificateHandleRSA, err)
	}

	// In some TPMs, when we read bytes from an NV index, the content read
	// includes the DER encoded x.509 certificate + trailing data. We need to
	// remove those trailing bytes in order to make the certificate parseable by
	// the server that uses x509.ParseCertificate().
	var ekCert asn1.RawValue
	_, err = asn1.Unmarshal(ekCertAndTrailingBytes, &ekCert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall certificate read from %08x: %w", EKCertificateHandleRSA, err)
	}

	return ekCert.FullBytes, nil
}

// GetEKPublic returns the public part of the Endorsement Key encoded in
// TPM wire format.
func (c *Session) GetEKPublic() ([]byte, error) {
	publicEK, _, _, err := tpm2.ReadPublic(c.rwc, c.ekHandle)
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
func (c *Session) loadKey(pubKey, privKey []byte, parentKeyPassword, keyPassword string) (*SigningKey, error) {
	pub, err := tpm2.DecodePublic(pubKey)
	if err != nil {
		return nil, fmt.Errorf("tpm2.DecodePublic failed: %w", err)
	}

	canSign := pub.Attributes&tpm2.FlagSign != 0
	if !canSign {
		return nil, errors.New("not a signing key")
	}

	var sigHashAlg tpm2.Algorithm
	var srkTemplate tpm2.Public
	switch pub.Type {
	case tpm2.AlgRSA:
		srkTemplate = SRKTemplateHighRSA()
		rsaParams := pub.RSAParameters
		if rsaParams != nil {
			sigHashAlg = rsaParams.Sign.Hash
		}

	case tpm2.AlgECC:
		srkTemplate = SRKTemplateHighECC()
		eccParams := pub.ECCParameters
		if eccParams != nil {
			sigHashAlg = eccParams.Sign.Hash
		}

	default:
		return nil, fmt.Errorf("bad key type: 0x%04x", pub.Type)
	}

	if sigHashAlg.IsNull() {
		return nil, errors.New("signature hash algorithm is NULL")
	}

	srkHandle, _, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(c.rwc, tpm2.HandleOwner,
			tpm2.PCRSelection{},
			c.ownerHierarchyPassword,
			parentKeyPassword,
			srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("tpm2.CreatePrimaryEx failed: %w", err)
	}
	defer c.flushContext(srkHandle)

	keyHandle, _, err := tpm2.Load(c.rwc, srkHandle, parentKeyPassword, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Load failed: %w", err)
	}

	return &SigningKey{
		Handle:     keyHandle,
		sigHashAlg: sigHashAlg,
		rw:         c.rwc,
		log:        c.log,
		password:   keyPassword,
	}, nil
}

func (c *Session) createAttestationKey(parentKeyPassword, keyPassword string) ([]byte, []byte, error) {
	srkHandle, _, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(c.rwc,
			tpm2.HandleOwner,
			tpm2.PCRSelection{},
			c.ownerHierarchyPassword,
			parentKeyPassword,
			SRKTemplateHighRSA())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SRK: %w", err)
	}
	defer c.flushContext(srkHandle)

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(
		c.rwc,
		srkHandle,
		tpm2.PCRSelection{},
		parentKeyPassword,
		keyPassword,
		client.AKTemplateRSA(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AK: %w", err)
	}

	return privBlob, pubBlob, nil
}

// createPolicySessionForEK creates a session-based authorization to access EK.
// We need a session-based authorization to run the activate credential command
// (password-based auth is not enough) because of the attributes of the EK template.
func (c *Session) createPolicySessionForEK() (tpmutil.Handle, error) {
	// The TPM is accesed in a plain session (we assume the bus is trusted) so we use an:
	// un-bounded and un-salted policy session (bindKey = HandleNull, tpmKey = HandleNull, secret = nil,
	// (sym = algNull, nonceCaller = all zeros).

	// A detailed description of this command and its parameters can be found in TCG spec:
	// https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf#page=52
	hSession, _, err := tpm2.StartAuthSession(
		c.rwc,              // rw:		TPM channel.
		tpm2.HandleNull,    // tpmKey:		Handle to a key to do the decryption of encryptedSalt.
		tpm2.HandleNull,    // bindKey:		Handle to a key to bind this session to (concatenates to salt).
		make([]byte, 16),   // nonceCaller:	Initial nonce from the caller.
		nil,                // secret:		Encrypted salt.
		tpm2.SessionPolicy, // se:		Session type.
		tpm2.AlgNull,       // sym:		The type of parameter encryption that will be used when the session is set for encrypt or decrypt.
		tpm2.AlgSHA256,     // hashAlg:		The hash algorithm used in computation of the policy digest.
	)
	if err != nil {
		return 0, err
	}

	// A detailed description of this command and its parameters can be found in TCG spec:
	// https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf#page=228
	_, _, err = tpm2.PolicySecret(
		c.rwc,                  // 	rw:		TPM channel.
		tpm2.HandleEndorsement, // 	entityHandle:	handle for an entity providing the authorization.
		tpm2.AuthCommand{ // 		entityAuth:	entity authorization.
			Session: tpm2.HandlePasswordSession,
			Auth:    []byte(c.endorsementHierarchyPassword),
		},
		hSession, // policyHandle:	Handle for the policy session being extended.
		nil,      // policyNonce:	The policy nonce for the session (can be the Empty Buffer).
		nil,      // cpHash:		Digest of the command parameters to which this authorization is limited (if it is not limited, the parameter will be the Empty Buffer).
		nil,      // policyRef:		Reference to a policy relating to the authorization.
		0,        // expiry: 		Time when authorization will expire measured in seconds (zero means no expiration).
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

func newRandomPassword() (string, error) {
	rndBytes, err := tpmdevid.GetRandomBytes(randomPasswordSize)
	if err != nil {
		return "", err
	}
	return string(rndBytes), nil
}
