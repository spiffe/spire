package hashicorpvault

import (
	"testing"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/server/common/vault"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestGetKeyEntry(t *testing.T) {
	const pubKeyP256 = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n"

	for _, tt := range []struct {
		name       string
		entry      *vault.KeyEntry
		expectID   string
		expectType keymanagerv1.KeyType
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "ecdsa-p256 key",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{
					"creation_time": "2024-09-16T18:18:54.284635756Z",
					"public_key":    pubKeyP256,
				},
			},
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_EC_P256,
		},
		{
			name: "ecdsa-p384 key",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "ecdsa-p384",
				KeyData: map[string]any{
					"public_key": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXpDQLh6ct/CJuMV2UIXnm/GilDNgy6Qy\ngzGhGsRaGrlYtM8g3sSHoGBIR+wT2hIF0ryY4mqYPtzw39WiHSdK3J985iX/bMXD\npr5xe142+1uHbJdKfSD5LrycBBtIsoEH\n-----END PUBLIC KEY-----\n",
				},
			},
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_EC_P384,
		},
		{
			name: "rsa-2048 key",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "rsa-2048",
				KeyData: map[string]any{
					"public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnV4uS61DWBvfbpzuHzIQ\nRbPZfLbe5wolynACSBNB4DxskuAZOg27e9wKUVwg82gOFPM4t1mVMHYee2OqEspZ\n5zL6y5bfwK//F+H8B6egitPKcHIv6WtErCrl3NM7V8jv4JIxmSeLRFNLpsGPp2dc\nZ/Q/SwprFhMfBiskCmOf+FlOrLZXe7a6Wsfe2yTJIwC5zGn+jNPVBmscHqjzttME\n4/xoZxCg13uZa1rskIOW526RT7ccfIMo8qGoZ0KVjnAJGuTwhFvJ+D/jwhHDylsP\n1ngHgJlBnDo23GouQD13TRaRUamTb4sliRAFdrWwK3j9YaOgtJnBYikkG1T/SSsm\nMQIDAQAB\n-----END PUBLIC KEY-----\n",
				},
			},
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_RSA_2048,
		},
		{
			name: "rsa-4096 key",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "rsa-4096",
				KeyData: map[string]any{
					"public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsmp4dJSfPGDGhmWoBD7G\nYPBQ/KGCR8/huy7/bjNRprKKpnhDl+4y5OaQVUqvFnoJZYfQvowcaGrARwBrsvPw\nkwPe6dB33XZBCWWDIvMORAQhgGeQF0MRjKibxDxlwPLZLARnHF8674gDdbL7Tg/G\nxQqThWNqVk6/GiHnAjkBntyw3V5XI5RtmpdSLDcZOUdqh/Bwi6fGOwtW1kU2NVSG\nalhdQu1O2Pr72sVZ/9+LwMYv1ZI0lFULwr7ZaIo86+vei4BIk+Pd/kkOjn9KKJD1\n84eL1QnN03XPc9ENCt7rF/R+IT7YkoqCDBZawW6VpexrA6QxtxUO0DcAffIFJ61Z\n9N7p3VULjZZIJmpOaMTEu3wFritcTBZweI3gikisg3YMqRDzC97+WqKUGpWUfGcF\ngENRvqIlE05snmmwziGB4Rey3yAqZBHSXRWFWKdDX/X7gMEJ4Av7hAumMxgR34If\ndzEShW6ushnOEtlXQR0/DE814GBWI0+oa+w9m20XkzL60bUIZevP9mOhbSNxuN8m\naCDOjIa7qeX3yg1l4+dnAZ/S8O+K3GEWkqWwq/FXH1EfCGeztp2b0pN8n0r0Tr3S\nHkHMNNEXovlQevgEFEc01Kg8PXBDd1hP31dfMfZ6v+BXygGHg95zR4AFpcRIYJWu\n9dmMkmMWQN5rZeyDO7ZfDQ0CAwEAAQ==\n-----END PUBLIC KEY-----\n",
				},
			},
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_RSA_4096,
		},
		{
			name: "key name too short to contain UUID prefix",
			entry: &vault.KeyEntry{
				KeyName: "short",
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{},
			},
			expectCode: codes.Internal,
			expectMsg:  "unable to get SPIRE key ID from key short",
		},
		{
			name: "missing public_key field",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{},
			},
			expectCode: codes.Internal,
			expectMsg:  "expected public key to be present",
		},
		{
			name: "malformed PEM public key",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{
					"public_key": "-----BEGIN MALFORMED KEY-----\nMIICIjAN\n-----END MALFORMED KEY-----\n",
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "unable to decode PEM key",
		},
		{
			name: "unsupported key type",
			entry: &vault.KeyEntry{
				KeyName: "ab748227-3a10-40cc-87fd-2a5321aa638d-x509-CA-A",
				KeyType: "ed25519",
				KeyData: map[string]any{
					"public_key": pubKeyP256,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "unsupported key type: ed25519",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ke, err := getKeyEntry(tt.entry)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
				require.Nil(t, ke)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectID, ke.PublicKey.Id)
			require.Equal(t, tt.expectType, ke.PublicKey.Type)
			require.NotEmpty(t, ke.PublicKey.PkixData)
			require.NotEmpty(t, ke.PublicKey.Fingerprint)
		})
	}
}
