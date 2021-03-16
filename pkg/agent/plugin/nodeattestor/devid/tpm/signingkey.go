package tpm

import (
	"fmt"
	"io"
	"time"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// maxAttempts indicates the max number retries for running TPM commands when
// TPM responds with a tpm2.RCRetry code.
const maxAttempts = 10

// SigningKey represents a TPM loaded key
type SigningKey struct {
	Handle     tpmutil.Handle
	sigHashAlg tpm2.Algorithm
	rw         io.ReadWriter
	log        hclog.Logger
}

// LoadSigningKey loads the given keypair into the provided TPM
func LoadSigningKey(rw io.ReadWriter, pubKey, privKey []byte, log hclog.Logger) (*SigningKey, error) {
	pub, err := tpm2.DecodePublic(pubKey)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Public decoding failed: %w", err)
	}

	canSign := pub.Attributes&tpm2.FlagSign != 0
	if !canSign {
		return nil, fmt.Errorf("not a signing key")
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
		srkTemplate = tpm2tools.SRKTemplateECC()
		eccParams := pub.ECCParameters
		if eccParams != nil {
			sigHashAlg = eccParams.Sign.Hash
		}

	default:
		return nil, fmt.Errorf("bad key type: 0x%04x", pub.Type)
	}

	if sigHashAlg.IsNull() {
		return nil, fmt.Errorf("signature hash algorithm is NULL")
	}

	srk, err := tpm2tools.NewKey(rw, tpm2.HandleOwner, srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("SRK creation failed: %w", err)
	}

	defer srk.Close()

	keyHandle, _, err := tpm2.Load(rw, srk.Handle(), "", pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Load failed: %w", err)
	}

	return &SigningKey{
		Handle:     keyHandle,
		sigHashAlg: sigHashAlg,
		rw:         rw,
		log:        log,
	}, nil
}

// Close removes the key from the TPM
func (k *SigningKey) Close() error {
	return tpm2.FlushContext(k.rw, k.Handle)
}

// Sign request the TPM to sign the given data using this key
func (k *SigningKey) Sign(data []byte) ([]byte, error) {
	digest, token, err := tpm2.Hash(k.rw, k.sigHashAlg, data, tpm2.HandlePlatform)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Hash failed: %w", err)
	}

	var sig *tpm2.Signature
	for i := 0; i <= maxAttempts; i++ {
		sig, err = tpm2.Sign(k.rw, k.Handle, "", digest, token, nil)
		switch {
		case err == nil:
			break

		case isRetry(err):
			if i == maxAttempts {
				return nil, fmt.Errorf("max attempts reached: %w", err)
			}

			k.log.Debug(fmt.Sprintf("TPM was not able to start the command 'Sign'. Retrying: attempt (%d/%d)", i, maxAttempts))
			time.Sleep(time.Millisecond * 500)
			continue

		default:
			return nil, fmt.Errorf("tpm2.Sign failed: %w", err)
		}
	}

	if sig.RSA != nil {
		return sig.RSA.Signature, nil
	}

	if sig.ECC != nil {
		var b cryptobyte.Builder
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(sig.ECC.R)
			b.AddASN1BigInt(sig.ECC.S)
		})

		return b.Bytes()
	}

	return nil, fmt.Errorf("bad tpm2.Signature")
}

// Certify calls tpm2.Certify using the current key as signer and the provided
// object as object handle.
func (k *SigningKey) Certify(object tpmutil.Handle) ([]byte, []byte, error) {
	// For some reason 'tpm2.Certify()' sometimes fails the first attempt and asks for retry.
	// So, we retry some times in case of getting the RCRetry error.
	// It seems that this issue has been reported: https://github.com/google/go-tpm/issues/59
	var certifiedDevID []byte
	var certificationSignature []byte
	var err error
	for i := 0; i <= maxAttempts; i++ {
		certifiedDevID, certificationSignature, err = tpm2.Certify(k.rw, "", "", object, k.Handle, nil)
		switch {
		case err == nil:
			return certifiedDevID, certificationSignature, nil

		case isRetry(err):
			if i == maxAttempts {
				return nil, nil, fmt.Errorf("max attempts reached: %w", err)
			}

			k.log.Debug(fmt.Sprintf("TPM was not able to start the command 'Certify'. Retrying: attempt (%d/%d)", i, maxAttempts))
			time.Sleep(time.Millisecond * 500)

		default:
			break
		}
	}

	return nil, nil, fmt.Errorf("certify failed: %w", err)
}

// SRKTemplateHighRSA returns the default high range SRK template (called H-1 in the specification).
// https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/
func SRKTemplateHighRSA() tpm2.Public {
	// The tpm2tools library does not have a function to build the high range template
	// so we build it based on the previous template.
	template := tpm2tools.SRKTemplateRSA()
	template.RSAParameters.ModulusRaw = []byte{}
	return template
}

// isRetry returns true if the given error is a tpm2.Warning that request retry.
func isRetry(err error) bool {
	warn, ok := err.(tpm2.Warning)
	return ok && warn.Code == tpm2.RCRetry
}
