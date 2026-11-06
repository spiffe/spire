package x509pop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var testECDSAP384Key = testkey.MustEC384()

// legacyChallenge mirrors the challenge representation used before hash
// selection was introduced. It is used to reproduce how peers that predate
// the hash field serialize and parse challenges.
type legacyChallenge struct {
	RSASignature   *RSASignatureChallenge   `json:"rsa_signature"`
	ECDSASignature *ECDSASignatureChallenge `json:"ecdsa_signature"`
}

// legacyCalculateResponse reproduces the response calculation of agents that
// predate hash selection: the challenge is parsed without the hash field and
// the combined nonces are always signed using SHA-256.
func legacyCalculateResponse(t *testing.T, privateKey any, challengeBytes []byte) *Response {
	challenge := new(legacyChallenge)
	require.NoError(t, json.Unmarshal(challengeBytes, challenge))
	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		require.NotNil(t, challenge.RSASignature)
		resp, err := CalculateRSASignatureResponse(privateKey, challenge.RSASignature)
		require.NoError(t, err)
		return &Response{RSASignature: resp}
	case *ecdsa.PrivateKey:
		require.NotNil(t, challenge.ECDSASignature)
		resp, err := CalculateECDSASignatureResponse(privateKey, challenge.ECDSASignature)
		require.NoError(t, err)
		return &Response{ECDSASignature: resp}
	default:
		require.FailNow(t, "unexpected key type")
		return nil
	}
}

type hashTestKey struct {
	name       string
	privateKey crypto.Signer
}

func hashTestKeys() []hashTestKey {
	return []hashTestKey{
		{name: "RSA-2048", privateKey: testRSAKey},
		{name: "ECDSA-P256", privateKey: testECDSAKey},
		{name: "ECDSA-P384", privateKey: testECDSAP384Key},
	}
}

func TestParseHashAlgorithm(t *testing.T) {
	for _, tt := range []struct {
		name      string
		expect    crypto.Hash
		expectErr string
	}{
		{name: "", expect: crypto.SHA256},
		{name: "sha256", expect: crypto.SHA256},
		{name: "sha384", expect: crypto.SHA384},
		{name: "SHA384", expectErr: `unsupported hash algorithm "SHA384"`},
		{name: "sha512", expectErr: `unsupported hash algorithm "sha512"`},
		{name: "sha1", expectErr: `unsupported hash algorithm "sha1"`},
		{name: "md5", expectErr: `unsupported hash algorithm "md5"`},
	} {
		t.Run("hash "+tt.name, func(t *testing.T) {
			hash, err := ParseHashAlgorithm(tt.name)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, hash)
		})
	}
}

func TestChallengeResponseWithHash(t *testing.T) {
	for _, key := range hashTestKeys() {
		cert, err := createCertificate(key.privateKey, key.privateKey.Public())
		require.NoError(t, err)

		for _, tt := range []struct {
			hash             string
			expectWireHash   string
			expectDigestSize int
		}{
			{hash: "", expectWireHash: "", expectDigestSize: 32},
			{hash: HashSHA256, expectWireHash: "", expectDigestSize: 32},
			{hash: HashSHA384, expectWireHash: HashSHA384, expectDigestSize: 48},
		} {
			t.Run(key.name+"/hash="+tt.hash, func(t *testing.T) {
				challenge, err := GenerateChallengeWithHash(cert, tt.hash)
				require.NoError(t, err)
				require.Equal(t, tt.expectWireHash, challenge.Hash)

				// The challenge must survive the JSON round trip performed by
				// the plugin protocol.
				challengeBytes, err := json.Marshal(challenge)
				require.NoError(t, err)
				parsed := new(Challenge)
				require.NoError(t, json.Unmarshal(challengeBytes, parsed))

				response, err := CalculateResponse(key.privateKey, parsed)
				require.NoError(t, err)
				responseBytes, err := json.Marshal(response)
				require.NoError(t, err)
				parsedResponse := new(Response)
				require.NoError(t, json.Unmarshal(responseBytes, parsedResponse))

				require.NoError(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, parsedResponse))

				// Nonce lengths are unchanged regardless of the hash.
				var challengeNonce, responseNonce []byte
				if challenge.RSASignature != nil {
					challengeNonce, responseNonce = challenge.RSASignature.Nonce, parsedResponse.RSASignature.Nonce
				} else {
					challengeNonce, responseNonce = challenge.ECDSASignature.Nonce, parsedResponse.ECDSASignature.Nonce
				}
				require.Len(t, challengeNonce, nonceLen)
				require.Len(t, responseNonce, nonceLen)

				hash, err := ParseHashAlgorithm(challenge.Hash)
				require.NoError(t, err)
				digest, err := combineNoncesWithHash(challengeNonce, responseNonce, hash)
				require.NoError(t, err)
				require.Len(t, digest, tt.expectDigestSize)
			})
		}
	}
}

func TestDefaultChallengeWireFormatUnchanged(t *testing.T) {
	cert, err := createCertificate(testRSAKey, &testRSAKey.PublicKey)
	require.NoError(t, err)

	for _, generate := range []func() (*Challenge, error){
		func() (*Challenge, error) { return GenerateChallenge(cert) },
		func() (*Challenge, error) { return GenerateChallengeWithHash(cert, "") },
		func() (*Challenge, error) { return GenerateChallengeWithHash(cert, HashSHA256) },
	} {
		challenge, err := generate()
		require.NoError(t, err)
		challengeBytes, err := json.Marshal(challenge)
		require.NoError(t, err)

		fields := map[string]json.RawMessage{}
		require.NoError(t, json.Unmarshal(challengeBytes, &fields))
		require.NotContains(t, fields, "hash")

		legacyBytes, err := json.Marshal(legacyChallenge{RSASignature: challenge.RSASignature})
		require.NoError(t, err)
		require.JSONEq(t, string(legacyBytes), string(challengeBytes))
	}

	challenge, err := GenerateChallengeWithHash(cert, HashSHA384)
	require.NoError(t, err)
	challengeBytes, err := json.Marshal(challenge)
	require.NoError(t, err)
	require.Contains(t, string(challengeBytes), `"hash":"sha384"`)
}

func TestHashCompatibility(t *testing.T) {
	for _, key := range hashTestKeys() {
		cert, err := createCertificate(key.privateKey, key.privateKey.Public())
		require.NoError(t, err)

		t.Run(key.name+"/legacy verifier accepts new SHA-256 response", func(t *testing.T) {
			// A legacy server generated a challenge without the hash field and
			// verifies with the SHA-256 helpers.
			legacy := legacyChallenge{}
			if _, ok := key.privateKey.(*rsa.PrivateKey); ok {
				legacy.RSASignature, err = GenerateRSASignatureChallenge()
			} else {
				legacy.ECDSASignature, err = GenerateECDSASignatureChallenge()
			}
			require.NoError(t, err)
			challengeBytes, err := json.Marshal(legacy)
			require.NoError(t, err)

			parsed := new(Challenge)
			require.NoError(t, json.Unmarshal(challengeBytes, parsed))
			require.Empty(t, parsed.Hash)
			response, err := CalculateResponse(key.privateKey, parsed)
			require.NoError(t, err)

			switch pub := key.privateKey.Public().(type) {
			case *rsa.PublicKey:
				require.NoError(t, VerifyRSASignatureResponse(pub, legacy.RSASignature, response.RSASignature))
			case *ecdsa.PublicKey:
				require.NoError(t, VerifyECDSASignatureResponse(pub, legacy.ECDSASignature, response.ECDSASignature))
			}
		})

		t.Run(key.name+"/new SHA-256 verifier accepts legacy response", func(t *testing.T) {
			challenge, err := GenerateChallengeWithHash(cert, HashSHA256)
			require.NoError(t, err)
			challengeBytes, err := json.Marshal(challenge)
			require.NoError(t, err)
			response := legacyCalculateResponse(t, key.privateKey, challengeBytes)
			require.NoError(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response))
		})

		t.Run(key.name+"/new SHA-384 verifier rejects legacy response", func(t *testing.T) {
			challenge, err := GenerateChallengeWithHash(cert, HashSHA384)
			require.NoError(t, err)
			challengeBytes, err := json.Marshal(challenge)
			require.NoError(t, err)
			response := legacyCalculateResponse(t, key.privateKey, challengeBytes)
			require.Error(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response))
		})

		t.Run(key.name+"/SHA-256 verifier rejects SHA-384 response", func(t *testing.T) {
			challenge, err := GenerateChallengeWithHash(cert, HashSHA384)
			require.NoError(t, err)
			response, err := CalculateResponse(key.privateKey, challenge)
			require.NoError(t, err)

			challenge.Hash = ""
			require.Error(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response))
			challenge.Hash = HashSHA256
			require.Error(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response))
		})
	}
}

func TestUnsupportedChallengeHash(t *testing.T) {
	for _, key := range hashTestKeys() {
		t.Run(key.name, func(t *testing.T) {
			cert, err := createCertificate(key.privateKey, key.privateKey.Public())
			require.NoError(t, err)

			_, err = GenerateChallengeWithHash(cert, "sha512")
			require.EqualError(t, err, `unsupported hash algorithm "sha512"`)

			challenge, err := GenerateChallengeWithHash(cert, HashSHA384)
			require.NoError(t, err)
			response, err := CalculateResponse(key.privateKey, challenge)
			require.NoError(t, err)

			challenge.Hash = "md5"
			_, err = CalculateResponse(key.privateKey, challenge)
			require.EqualError(t, err, `unsupported hash algorithm "md5"`)
			err = VerifyChallengeResponse(key.privateKey.Public(), challenge, response)
			require.EqualError(t, err, `unsupported hash algorithm "md5"`)
		})
	}
}

func TestTamperedSignatureWithSHA384(t *testing.T) {
	for _, key := range hashTestKeys() {
		t.Run(key.name, func(t *testing.T) {
			cert, err := createCertificate(key.privateKey, key.privateKey.Public())
			require.NoError(t, err)
			challenge, err := GenerateChallengeWithHash(cert, HashSHA384)
			require.NoError(t, err)

			response, err := CalculateResponse(key.privateKey, challenge)
			require.NoError(t, err)
			if response.RSASignature != nil {
				response.RSASignature.Signature[0]++
				require.EqualError(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response), "RSA signature verify failed")
				return
			}

			response.ECDSASignature.R[0]++
			require.EqualError(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response), "ECDSA signature verify failed")

			response, err = CalculateResponse(key.privateKey, challenge)
			require.NoError(t, err)
			response.ECDSASignature.S[0]++
			require.EqualError(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response), "ECDSA signature verify failed")

			response, err = CalculateResponse(key.privateKey, challenge)
			require.NoError(t, err)
			response.ECDSASignature.Nonce[0]++
			require.EqualError(t, VerifyChallengeResponse(key.privateKey.Public(), challenge, response), "ECDSA signature verify failed")
		})
	}
}

func TestInvalidNonceLengthsWithHash(t *testing.T) {
	valid := make([]byte, nonceLen)
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		for _, tt := range []struct {
			desc      string
			challenge []byte
			response  []byte
			expectErr string
		}{
			{desc: "short challenge", challenge: valid[:nonceLen-1], response: valid, expectErr: "invalid challenge nonce"},
			{desc: "long challenge", challenge: make([]byte, nonceLen+1), response: valid, expectErr: "invalid challenge nonce"},
			{desc: "empty challenge", challenge: nil, response: valid, expectErr: "invalid challenge nonce"},
			{desc: "short response", challenge: valid, response: valid[:nonceLen-1], expectErr: "invalid response nonce"},
			{desc: "long response", challenge: valid, response: make([]byte, 48), expectErr: "invalid response nonce"},
			{desc: "empty response", challenge: valid, response: nil, expectErr: "invalid response nonce"},
		} {
			t.Run(hash.String()+"/"+tt.desc, func(t *testing.T) {
				_, err := combineNoncesWithHash(tt.challenge, tt.response, hash)
				require.EqualError(t, err, tt.expectErr)
			})
		}
	}

	_, err := combineNoncesWithHash(valid, valid, crypto.SHA512)
	require.EqualError(t, err, "unsupported hash algorithm SHA-512")

	cert, err := createCertificate(testECDSAP384Key, &testECDSAP384Key.PublicKey)
	require.NoError(t, err)
	challenge, err := GenerateChallengeWithHash(cert, HashSHA384)
	require.NoError(t, err)
	challenge.ECDSASignature.Nonce = challenge.ECDSASignature.Nonce[:16]
	_, err = CalculateResponse(testECDSAP384Key, challenge)
	require.EqualError(t, err, "invalid challenge nonce")
}

func TestCombineNoncesSHA256Unchanged(t *testing.T) {
	// The SHA-256 digest must stay SHA-256(challenge || response), as it was
	// computed before hash selection was introduced.
	challenge := make([]byte, nonceLen)
	response := make([]byte, nonceLen)
	for i := range challenge {
		challenge[i] = byte(i)
		response[i] = byte(0xff - i)
	}
	sha256Digest, err := combineNoncesWithHash(challenge, response, crypto.SHA256)
	require.NoError(t, err)

	h := crypto.SHA256.New()
	_, _ = h.Write(challenge)
	_, _ = h.Write(response)
	require.Equal(t, h.Sum(nil), sha256Digest)

	h = crypto.SHA384.New()
	_, _ = h.Write(challenge)
	_, _ = h.Write(response)
	sha384Digest, err := combineNoncesWithHash(challenge, response, crypto.SHA384)
	require.NoError(t, err)
	require.Equal(t, h.Sum(nil), sha384Digest)
}
