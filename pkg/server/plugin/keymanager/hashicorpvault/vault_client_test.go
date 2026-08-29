package hashicorpvault

import (
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/pkg/server/common/vault"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestParseKeyCreationTime(t *testing.T) {
	for _, tt := range []struct {
		name       string
		keyData    map[string]any
		expectTime time.Time
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name:       "valid RFC3339Nano",
			keyData:    map[string]any{"creation_time": "2024-09-16T18:18:54.284635756Z"},
			expectTime: time.Date(2024, 9, 16, 18, 18, 54, 284635756, time.UTC),
		},
		{
			name:       "missing creation_time",
			keyData:    map[string]any{},
			expectCode: codes.Internal,
			expectMsg:  "key data is missing creation_time",
		},
		{
			name:       "non-string creation_time",
			keyData:    map[string]any{"creation_time": 12345},
			expectCode: codes.Internal,
			expectMsg:  "expected creation_time type string",
		},
		{
			name:       "invalid time format",
			keyData:    map[string]any{"creation_time": "not-a-time"},
			expectCode: codes.Internal,
			expectMsg:  "failed to parse creation_time",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyCreationTime(tt.keyData)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectTime, got)
		})
	}
}

func TestSetCache(t *testing.T) {
	const (
		testServerID  = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		testUUID1     = "11111111-1111-1111-1111-111111111111"
		testUUID2     = "22222222-2222-2222-2222-222222222222"
		otherServerID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		spireKeyID    = "x509-CA-A"
		pubKeyP256    = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n"
	)

	olderKey := &vault.KeyEntry{
		KeyName: testServerID + "-" + testUUID1 + "-" + spireKeyID,
		KeyType: "ecdsa-p256",
		KeyData: map[string]any{"creation_time": "2024-01-01T00:00:00Z", "public_key": pubKeyP256},
	}
	newerKey := &vault.KeyEntry{
		KeyName: testServerID + "-" + testUUID2 + "-" + spireKeyID,
		KeyType: "ecdsa-p256",
		KeyData: map[string]any{"creation_time": "2024-06-01T00:00:00Z", "public_key": pubKeyP256},
	}
	otherServerKey := &vault.KeyEntry{
		KeyName: otherServerID + "-" + testUUID1 + "-" + spireKeyID,
		KeyType: "ecdsa-p256",
		KeyData: map[string]any{"creation_time": "2024-06-01T00:00:00Z", "public_key": pubKeyP256},
	}

	newPlugin := func() *Plugin {
		return &Plugin{
			serverID:       testServerID,
			entries:        make(map[string]keyEntry),
			scheduleDelete: make(chan string, 120),
			logger:         hclog.NewNullLogger(),
		}
	}

	t.Run("single key is loaded", func(t *testing.T) {
		p := newPlugin()
		require.NoError(t, p.setCache([]*vault.KeyEntry{newerKey}))
		require.Len(t, p.entries, 1)
		require.Equal(t, newerKey.KeyName, p.entries[spireKeyID].KeyName)
		require.Empty(t, p.scheduleDelete)
	})

	t.Run("key from other server is skipped", func(t *testing.T) {
		p := newPlugin()
		require.NoError(t, p.setCache([]*vault.KeyEntry{otherServerKey}))
		require.Empty(t, p.entries)
		require.Empty(t, p.scheduleDelete)
	})

	t.Run("on duplicate older first, newer kept and older scheduled for deletion", func(t *testing.T) {
		p := newPlugin()
		require.NoError(t, p.setCache([]*vault.KeyEntry{olderKey, newerKey}))
		require.Len(t, p.entries, 1)
		require.Equal(t, newerKey.KeyName, p.entries[spireKeyID].KeyName)
		require.Len(t, p.scheduleDelete, 1)
		require.Equal(t, olderKey.KeyName, <-p.scheduleDelete)
	})

	t.Run("on duplicate newer first, newer kept and older scheduled for deletion", func(t *testing.T) {
		p := newPlugin()
		require.NoError(t, p.setCache([]*vault.KeyEntry{newerKey, olderKey}))
		require.Len(t, p.entries, 1)
		require.Equal(t, newerKey.KeyName, p.entries[spireKeyID].KeyName)
		require.Len(t, p.scheduleDelete, 1)
		require.Equal(t, olderKey.KeyName, <-p.scheduleDelete)
	})

	t.Run("missing creation_time returns error", func(t *testing.T) {
		p := newPlugin()
		badKey := &vault.KeyEntry{
			KeyName: testServerID + "-" + testUUID1 + "-" + spireKeyID,
			KeyType: "ecdsa-p256",
			KeyData: map[string]any{"public_key": pubKeyP256},
		}
		err := p.setCache([]*vault.KeyEntry{badKey})
		spiretest.RequireGRPCStatusHasPrefix(t, err, codes.Internal, "key data is missing creation_time")
	})
}

func TestEnqueueDelete(t *testing.T) {
	newPlugin := func(chanCap int) *Plugin {
		return &Plugin{
			scheduleDelete: make(chan string, chanCap),
			logger:         hclog.NewNullLogger(),
		}
	}

	t.Run("key name is sent to channel", func(t *testing.T) {
		p := newPlugin(1)
		p.enqueueDelete("old-key-name")
		require.Len(t, p.scheduleDelete, 1)
		require.Equal(t, "old-key-name", <-p.scheduleDelete)
	})

	t.Run("full channel does not block", func(t *testing.T) {
		p := newPlugin(0)
		// Must complete without blocking; if enqueueDelete blocks the test hangs.
		done := make(chan struct{})
		go func() {
			p.enqueueDelete("old-key-name")
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("enqueueDelete blocked on a full channel")
		}
		require.Empty(t, p.scheduleDelete)
	})
}

func TestGetKeyEntry(t *testing.T) {
	const (
		testServerID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		testUUID     = "ab748227-3a10-40cc-87fd-2a5321aa638d"
		// Key name format: <serverID>-<uuid>-<spireKeyID>
		testKeyName = testServerID + "-" + testUUID + "-x509-CA-A"
		pubKeyP256  = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV57LFbIQZzyZ2YcKZfB9mGWkUhJv\niRzIZOqV4wRHoUOZjMuhBMR2WviEsy65TYpcBjreAc6pbneiyhlTwPvgmw==\n-----END PUBLIC KEY-----\n"
	)

	for _, tt := range []struct {
		name       string
		entry      *vault.KeyEntry
		serverID   string
		expectID   string
		expectType keymanagerv1.KeyType
		expectCode codes.Code
		expectMsg  string
		expectSkip bool
	}{
		{
			name: "ecdsa-p256 key",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{
					"creation_time": "2024-09-16T18:18:54.284635756Z",
					"public_key":    pubKeyP256,
				},
			},
			serverID:   testServerID,
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_EC_P256,
		},
		{
			name: "ecdsa-p384 key",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "ecdsa-p384",
				KeyData: map[string]any{
					"public_key": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXpDQLh6ct/CJuMV2UIXnm/GilDNgy6Qy\ngzGhGsRaGrlYtM8g3sSHoGBIR+wT2hIF0ryY4mqYPtzw39WiHSdK3J985iX/bMXD\npr5xe142+1uHbJdKfSD5LrycBBtIsoEH\n-----END PUBLIC KEY-----\n",
				},
			},
			serverID:   testServerID,
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_EC_P384,
		},
		{
			name: "rsa-2048 key",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "rsa-2048",
				KeyData: map[string]any{
					"public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnV4uS61DWBvfbpzuHzIQ\nRbPZfLbe5wolynACSBNB4DxskuAZOg27e9wKUVwg82gOFPM4t1mVMHYee2OqEspZ\n5zL6y5bfwK//F+H8B6egitPKcHIv6WtErCrl3NM7V8jv4JIxmSeLRFNLpsGPp2dc\nZ/Q/SwprFhMfBiskCmOf+FlOrLZXe7a6Wsfe2yTJIwC5zGn+jNPVBmscHqjzttME\n4/xoZxCg13uZa1rskIOW526RT7ccfIMo8qGoZ0KVjnAJGuTwhFvJ+D/jwhHDylsP\n1ngHgJlBnDo23GouQD13TRaRUamTb4sliRAFdrWwK3j9YaOgtJnBYikkG1T/SSsm\nMQIDAQAB\n-----END PUBLIC KEY-----\n",
				},
			},
			serverID:   testServerID,
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_RSA_2048,
		},
		{
			name: "rsa-4096 key",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "rsa-4096",
				KeyData: map[string]any{
					"public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsmp4dJSfPGDGhmWoBD7G\nYPBQ/KGCR8/huy7/bjNRprKKpnhDl+4y5OaQVUqvFnoJZYfQvowcaGrARwBrsvPw\nkwPe6dB33XZBCWWDIvMORAQhgGeQF0MRjKibxDxlwPLZLARnHF8674gDdbL7Tg/G\nxQqThWNqVk6/GiHnAjkBntyw3V5XI5RtmpdSLDcZOUdqh/Bwi6fGOwtW1kU2NVSG\nalhdQu1O2Pr72sVZ/9+LwMYv1ZI0lFULwr7ZaIo86+vei4BIk+Pd/kkOjn9KKJD1\n84eL1QnN03XPc9ENCt7rF/R+IT7YkoqCDBZawW6VpexrA6QxtxUO0DcAffIFJ61Z\n9N7p3VULjZZIJmpOaMTEu3wFritcTBZweI3gikisg3YMqRDzC97+WqKUGpWUfGcF\ngENRvqIlE05snmmwziGB4Rey3yAqZBHSXRWFWKdDX/X7gMEJ4Av7hAumMxgR34If\ndzEShW6ushnOEtlXQR0/DE814GBWI0+oa+w9m20XkzL60bUIZevP9mOhbSNxuN8m\naCDOjIa7qeX3yg1l4+dnAZ/S8O+K3GEWkqWwq/FXH1EfCGeztp2b0pN8n0r0Tr3S\nHkHMNNEXovlQevgEFEc01Kg8PXBDd1hP31dfMfZ6v+BXygGHg95zR4AFpcRIYJWu\n9dmMkmMWQN5rZeyDO7ZfDQ0CAwEAAQ==\n-----END PUBLIC KEY-----\n",
				},
			},
			serverID:   testServerID,
			expectID:   "x509-CA-A",
			expectType: keymanagerv1.KeyType_RSA_4096,
		},
		{
			name: "key name does not match server ID prefix",
			entry: &vault.KeyEntry{
				KeyName: "other-server-id-" + testUUID + "-x509-CA-A",
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{"public_key": pubKeyP256},
			},
			serverID:   testServerID,
			expectSkip: true,
		},
		{
			name: "key name too short to contain UUID portion after server ID",
			entry: &vault.KeyEntry{
				KeyName: testServerID + "-short",
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{},
			},
			serverID:   testServerID,
			expectSkip: true,
		},
		{
			name: "missing public_key field",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{},
			},
			serverID:   testServerID,
			expectCode: codes.Internal,
			expectMsg:  "expected public key to be present",
		},
		{
			name: "malformed PEM public key",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "ecdsa-p256",
				KeyData: map[string]any{
					"public_key": "-----BEGIN MALFORMED KEY-----\nMIICIjAN\n-----END MALFORMED KEY-----\n",
				},
			},
			serverID:   testServerID,
			expectCode: codes.Internal,
			expectMsg:  "unable to decode PEM key",
		},
		{
			name: "unsupported key type",
			entry: &vault.KeyEntry{
				KeyName: testKeyName,
				KeyType: "ed25519",
				KeyData: map[string]any{
					"public_key": pubKeyP256,
				},
			},
			serverID:   testServerID,
			expectCode: codes.Internal,
			expectMsg:  "unsupported key type: ed25519",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ke, ok, err := getKeyEntry(tt.entry, tt.serverID)
			if tt.expectSkip {
				require.NoError(t, err)
				require.False(t, ok)
				require.Nil(t, ke)
				return
			}
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)
				require.Nil(t, ke)
				return
			}

			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, tt.expectID, ke.PublicKey.Id)
			require.Equal(t, tt.expectType, ke.PublicKey.Type)
			require.NotEmpty(t, ke.PublicKey.PkixData)
			require.NotEmpty(t, ke.PublicKey.Fingerprint)
		})
	}
}
