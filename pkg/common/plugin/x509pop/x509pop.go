package x509pop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"path"
)

type AttestationData struct {
	// DER encoded x509 certificate chain leading back to the trusted root. The
	// leaf certificate comes first.
	Certificates [][]byte `json:"certificates"`
}

type RSASignatureChallenge struct {
	Nonce []byte `json:"nonce"`
}

type RSASignatureResponse struct {
	Signature []byte `json:"signature"`
}

type ECDSASignatureChallenge struct {
	Nonce []byte `json:"nonce"`
}

type ECDSASignatureResponse struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}

type Challenge struct {
	RSASignature   *RSASignatureChallenge   `json:"rsa_signature"`
	ECDSASignature *ECDSASignatureChallenge `json:"ecdsa_signature"`
}

type Response struct {
	RSASignature   *RSASignatureResponse   `json:"rsa_signature"`
	ECDSASignature *ECDSASignatureResponse `json:"ecdsa_signature"`
}

func GenerateChallenge(cert *x509.Certificate) (*Challenge, error) {
	// ensure that the public key is intended to be used for digital signatures
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return nil, errors.New("certificate not intended for digital signature use")
	}

	switch publicKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		challenge, err := GenerateRSASignatureChallenge()
		if err != nil {
			return nil, err
		}
		return &Challenge{
			RSASignature: challenge,
		}, nil
	case *ecdsa.PublicKey:
		challenge, err := GenerateECDSASignatureChallenge()
		if err != nil {
			return nil, err
		}
		return &Challenge{
			ECDSASignature: challenge,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func CalculateResponse(privateKey interface{}, challenge *Challenge) (*Response, error) {
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		rsaChallenge := challenge.RSASignature
		if rsaChallenge == nil {
			return nil, errors.New("expecting RSA challenge")
		}
		response, err := CalculateRSASignatureResponse(privateKey, rsaChallenge)
		if err != nil {
			return nil, err
		}
		return &Response{
			RSASignature: response,
		}, nil
	case *ecdsa.PrivateKey:
		if challenge.ECDSASignature == nil {
			return nil, errors.New("expecting ECDSA challenge")
		}
		response, err := CalculateECDSASignatureResponse(privateKey, challenge.ECDSASignature)
		if err != nil {
			return nil, err
		}
		return &Response{
			ECDSASignature: response,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func VerifyChallengeResponse(publicKey interface{}, challenge *Challenge, response *Response) error {
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		if challenge.RSASignature == nil {
			return errors.New("expecting RSA challenge")
		}
		if response.RSASignature == nil {
			return errors.New("expecting RSA response")
		}
		return VerifyRSASignatureResponse(publicKey, challenge.RSASignature, response.RSASignature)
	case *ecdsa.PublicKey:
		if challenge.ECDSASignature == nil {
			return errors.New("expecting ECDSA challenge")
		}
		if response.ECDSASignature == nil {
			return errors.New("expecting ECDSA response")
		}
		return VerifyECDSASignatureResponse(publicKey, challenge.ECDSASignature, response.ECDSASignature)
	default:
		return fmt.Errorf("unsupported private key type %T", publicKey)
	}
}

func GenerateRSASignatureChallenge() (*RSASignatureChallenge, error) {
	nonce, err := randBytes(32)
	if err != nil {
		return nil, err
	}

	return &RSASignatureChallenge{
		Nonce: nonce,
	}, nil
}

func CalculateRSASignatureResponse(privateKey *rsa.PrivateKey, challenge *RSASignatureChallenge) (*RSASignatureResponse, error) {
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, challenge.Nonce, nil)
	if err != nil {
		return nil, err
	}

	return &RSASignatureResponse{
		Signature: signature,
	}, nil
}

func VerifyRSASignatureResponse(publicKey *rsa.PublicKey, challenge *RSASignatureChallenge, response *RSASignatureResponse) error {
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, challenge.Nonce, response.Signature, nil); err != nil {
		return errors.New("RSA signature verify failed")
	}
	return nil
}

func GenerateECDSASignatureChallenge() (*ECDSASignatureChallenge, error) {
	nonce, err := randBytes(32)
	if err != nil {
		return nil, err
	}

	return &ECDSASignatureChallenge{
		Nonce: nonce,
	}, nil
}

func CalculateECDSASignatureResponse(privateKey *ecdsa.PrivateKey, challenge *ECDSASignatureChallenge) (*ECDSASignatureResponse, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, challenge.Nonce)
	if err != nil {
		return nil, err
	}

	return &ECDSASignatureResponse{
		R: r.Bytes(),
		S: s.Bytes(),
	}, nil
}

func VerifyECDSASignatureResponse(publicKey *ecdsa.PublicKey, challenge *ECDSASignatureChallenge, response *ECDSASignatureResponse) error {
	r := new(big.Int)
	r.SetBytes(response.R)
	s := new(big.Int)
	s.SetBytes(response.S)
	if !ecdsa.Verify(publicKey, challenge.Nonce, r, s) {
		return errors.New("ECDSA signature verify failed")
	}
	return nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func Fingerprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func SpiffeID(trustDomain string, cert *x509.Certificate) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "x509pop", Fingerprint(cert)),
	}
	return u.String()
}
