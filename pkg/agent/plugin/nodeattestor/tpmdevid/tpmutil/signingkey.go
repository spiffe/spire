package tpmutil

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/go-tpm-tools/client"
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
	password   string
}

// Close removes the key from the TPM
func (k *SigningKey) Close() error {
	return tpm2.FlushContext(k.rw, k.Handle)
}

// Sign requests the TPM to sign the given data using this key
func (k *SigningKey) Sign(data []byte) ([]byte, error) {
	digest, token, err := tpm2.Hash(k.rw, k.sigHashAlg, data, tpm2.HandlePlatform)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Hash failed: %w", err)
	}

	for i := 1; i <= maxAttempts; i++ {
		sig, err := tpm2.Sign(k.rw, k.Handle, k.password, digest, token, nil)
		switch {
		case err == nil:
			return getSignatureBytes(sig)

		case isRetry(err):
			k.log.Warn(fmt.Sprintf("TPM was not able to start the command 'Sign'. Retrying: attempt (%d/%d)", i, maxAttempts))
			time.Sleep(time.Millisecond * 500)
			continue

		default:
			return nil, fmt.Errorf("tpm2.Sign failed: %w", err)
		}
	}

	return nil, fmt.Errorf("max attempts reached while trying to sign payload: %w", err)
}

// Certify calls tpm2.Certify using the current key as signer and the provided
// handle as object.
func (k *SigningKey) Certify(object tpmutil.Handle, objectPassword string) ([]byte, []byte, error) {
	// For some reason 'tpm2.Certify()' sometimes fails the first attempt and asks for retry.
	// So, we retry some times in case of getting the RCRetry error.
	// It seems that this issue has been reported: https://github.com/google/go-tpm/issues/59
	var err error
	for i := 1; i <= maxAttempts; i++ {
		certifiedDevID, certificationSignature, err := tpm2.Certify(k.rw, objectPassword, k.password, object, k.Handle, nil)
		switch {
		case err == nil:
			return certifiedDevID, certificationSignature, nil

		case isRetry(err):
			k.log.Warn(fmt.Sprintf("TPM was not able to start the command 'Certify'. Retrying: attempt (%d/%d)", i, maxAttempts))
			time.Sleep(time.Millisecond * 500)

		default:
			return nil, nil, fmt.Errorf("tpm2.Certify failed: %w", err)
		}
	}

	return nil, nil, fmt.Errorf("max attempts reached while trying to certify key: %w", err)
}

// SRKTemplateHighRSA returns the default high range SRK template (called H-1 in the specification).
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf#page=41
func SRKTemplateHighRSA() tpm2.Public {
	// The client library does not have a function to build the high range template
	// so we build it based on the previous template.
	template := client.SRKTemplateRSA()
	template.RSAParameters.ModulusRaw = []byte{}
	return template
}

// SRKTemplateHighECC returns the default high range SRK template (called H-2 in the specification).
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf#page=42
func SRKTemplateHighECC() tpm2.Public {
	// The client library does not have a function to build the high range template
	// so we build it based on the previous template.
	template := client.SRKTemplateECC()
	template.ECCParameters.Point.XRaw = []byte{}
	template.ECCParameters.Point.YRaw = []byte{}
	return template
}

// isRetry returns true if the given error is a tpm2.Warning that requests retry.
func isRetry(err error) bool {
	target := &tpm2.Warning{Code: tpm2.RCRetry}
	if errors.As(err, target) && target.Code == tpm2.RCRetry {
		return true
	}
	return false
}

func getSignatureBytes(sig *tpm2.Signature) ([]byte, error) {
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

	return nil, errors.New("unrecognized tpm2.Signature")
}
