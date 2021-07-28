package jwtkey_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	expiresAt          = time.Now().Truncate(time.Second)
	publicKey          = testkey.MustEC256().Public()
	pkixBytes, _       = x509.MarshalPKIXPublicKey(publicKey)
	junk               = []byte("JUNK")
	jwtKeyGood         = jwtkey.JWTKey{ID: "ID", PublicKey: publicKey, ExpiresAt: expiresAt}
	jwtKeyNoKeyID      = jwtkey.JWTKey{PublicKey: publicKey, ExpiresAt: expiresAt}
	jwtKeyNoPublicKey  = jwtkey.JWTKey{ID: "ID", ExpiresAt: expiresAt}
	jwtKeyBadPublicKey = jwtkey.JWTKey{ID: "ID", PublicKey: junk, ExpiresAt: expiresAt}
	jwtKeyNoExpiresAt  = jwtkey.JWTKey{ID: "ID", PublicKey: publicKey}
	pluginGood         = &plugintypes.JWTKey{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	pluginNoKeyID      = &plugintypes.JWTKey{PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	pluginNoPublicKey  = &plugintypes.JWTKey{KeyId: "ID", ExpiresAt: expiresAt.Unix()}
	pluginBadPublicKey = &plugintypes.JWTKey{KeyId: "ID", PublicKey: junk, ExpiresAt: expiresAt.Unix()}
	pluginNoExpiresAt  = &plugintypes.JWTKey{KeyId: "ID", PublicKey: pkixBytes}
	commonGood         = &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes, NotAfter: expiresAt.Unix()}
	commonNoKeyID      = &common.PublicKey{PkixBytes: pkixBytes, NotAfter: expiresAt.Unix()}
	commonNoPublicKey  = &common.PublicKey{Kid: "ID", NotAfter: expiresAt.Unix()}
	commonBadPublicKey = &common.PublicKey{Kid: "ID", PkixBytes: junk, NotAfter: expiresAt.Unix()}
	commonNoExpiresAt  = &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes}
	apiGood            = &apitypes.JWTKey{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	apiNoKeyID         = &apitypes.JWTKey{PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	apiNoPublicKey     = &apitypes.JWTKey{KeyId: "ID", ExpiresAt: expiresAt.Unix()}
	apiBadPublicKey    = &apitypes.JWTKey{KeyId: "ID", PublicKey: junk, ExpiresAt: expiresAt.Unix()}
	apiNoExpiresAt     = &apitypes.JWTKey{KeyId: "ID", PublicKey: pkixBytes}
)

func TestFromCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in *common.PublicKey, expectOut jwtkey.JWTKey) {
		actualOut, err := jwtkey.FromCommonProto(in)
		require.NoError(t, err)
		assertJWTKeyEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertJWTKeyEqual(t, expectOut, jwtkey.RequireFromCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in *common.PublicKey, expectErr string) {
		actualOut, err := jwtkey.FromCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireFromCommonProto(in) })
	}

	assertOK(t, commonGood, jwtKeyGood)
	assertFail(t, commonNoKeyID, "missing key ID for JWT key")
	assertFail(t, commonNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, commonBadPublicKey, `failed to unmarshal public key for JWT key "ID": `)
	assertOK(t, commonNoExpiresAt, jwtKeyNoExpiresAt)
}

func TestFromCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*common.PublicKey, expectOut []jwtkey.JWTKey) {
		actualOut, err := jwtkey.FromCommonProtos(in)
		require.NoError(t, err)
		assertJWTKeysEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertJWTKeysEqual(t, expectOut, jwtkey.RequireFromCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*common.PublicKey, expectErr string) {
		actualOut, err := jwtkey.FromCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Nil(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireFromCommonProtos(in) })
	}

	assertOK(t, []*common.PublicKey{commonGood}, []jwtkey.JWTKey{jwtKeyGood})
	assertFail(t, []*common.PublicKey{commonNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in jwtkey.JWTKey, expectOut *common.PublicKey) {
		actualOut, err := jwtkey.ToCommonProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, jwtkey.RequireToCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in jwtkey.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToCommonProto(in) })
	}

	assertOK(t, jwtKeyGood, commonGood)
	assertFail(t, jwtKeyNoKeyID, "missing key ID for JWT key")
	assertFail(t, jwtKeyNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, jwtKeyBadPublicKey, `failed to marshal public key for JWT key "ID": `)
	assertOK(t, jwtKeyNoExpiresAt, commonNoExpiresAt)
}

func TestToCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []jwtkey.JWTKey, expectOut []*common.PublicKey) {
		actualOut, err := jwtkey.ToCommonProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, jwtkey.RequireToCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []jwtkey.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToCommonProtos(in) })
	}

	assertOK(t, []jwtkey.JWTKey{jwtKeyGood}, []*common.PublicKey{commonGood})
	assertFail(t, []jwtkey.JWTKey{jwtKeyNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.JWTKey, expectOut jwtkey.JWTKey) {
		actualOut, err := jwtkey.FromPluginProto(in)
		require.NoError(t, err)
		assertJWTKeyEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertJWTKeyEqual(t, expectOut, jwtkey.RequireFromPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *plugintypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.FromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireFromPluginProto(in) })
	}

	assertOK(t, pluginGood, jwtKeyGood)
	assertFail(t, pluginNoKeyID, "missing key ID for JWT key")
	assertFail(t, pluginNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, pluginBadPublicKey, `failed to unmarshal public key for JWT key "ID": `)
	assertOK(t, pluginNoExpiresAt, jwtKeyNoExpiresAt)
}

func TestFromPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*plugintypes.JWTKey, expectOut []jwtkey.JWTKey) {
		actualOut, err := jwtkey.FromPluginProtos(in)
		require.NoError(t, err)
		assertJWTKeysEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertJWTKeysEqual(t, expectOut, jwtkey.RequireFromPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*plugintypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.FromPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Nil(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireFromPluginProtos(in) })
	}

	assertOK(t, []*plugintypes.JWTKey{pluginGood}, []jwtkey.JWTKey{jwtKeyGood})
	assertFail(t, []*plugintypes.JWTKey{pluginNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in jwtkey.JWTKey, expectOut *plugintypes.JWTKey) {
		actualOut, err := jwtkey.ToPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, jwtkey.RequireToPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in jwtkey.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToPluginProto(in) })
	}

	assertOK(t, jwtKeyGood, pluginGood)
	assertFail(t, jwtKeyNoKeyID, "missing key ID for JWT key")
	assertFail(t, jwtKeyNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, jwtKeyBadPublicKey, `failed to marshal public key for JWT key "ID": `)
	assertOK(t, jwtKeyNoExpiresAt, pluginNoExpiresAt)
}

func TestToPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []jwtkey.JWTKey, expectOut []*plugintypes.JWTKey) {
		actualOut, err := jwtkey.ToPluginProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, jwtkey.RequireToPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []jwtkey.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToPluginProtos(in) })
	}

	assertOK(t, []jwtkey.JWTKey{jwtKeyGood}, []*plugintypes.JWTKey{pluginGood})
	assertFail(t, []jwtkey.JWTKey{jwtKeyNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToCommonFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.JWTKey, expectOut *common.PublicKey) {
		actualOut, err := jwtkey.ToCommonFromPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, jwtkey.RequireToCommonFromPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *plugintypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToCommonFromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToCommonFromPluginProto(in) })
	}

	assertOK(t, pluginGood, commonGood)
	assertFail(t, pluginNoKeyID, "missing key ID for JWT key")
	assertFail(t, pluginNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, pluginBadPublicKey, `failed to unmarshal public key for JWT key "ID": `)
	assertOK(t, pluginNoExpiresAt, commonNoExpiresAt)
}

func TestToCommonFromPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*plugintypes.JWTKey, expectOut []*common.PublicKey) {
		actualOut, err := jwtkey.ToCommonFromPluginProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, jwtkey.RequireToCommonFromPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*plugintypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToCommonFromPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToCommonFromPluginProtos(in) })
	}

	assertOK(t, []*plugintypes.JWTKey{pluginGood}, []*common.PublicKey{commonGood})
	assertFail(t, []*plugintypes.JWTKey{pluginNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToPluginFromCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in *common.PublicKey, expectOut *plugintypes.JWTKey) {
		actualOut, err := jwtkey.ToPluginFromCommonProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, jwtkey.RequireToPluginFromCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in *common.PublicKey, expectErr string) {
		actualOut, err := jwtkey.ToPluginFromCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToPluginFromCommonProto(in) })
	}

	assertOK(t, commonGood, pluginGood)
	assertFail(t, commonNoKeyID, "missing key ID for JWT key")
	assertFail(t, commonNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, commonBadPublicKey, `failed to unmarshal public key for JWT key "ID": `)
	assertOK(t, commonNoExpiresAt, pluginNoExpiresAt)
}

func TestToPluginFromCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*common.PublicKey, expectOut []*plugintypes.JWTKey) {
		actualOut, err := jwtkey.ToPluginFromCommonProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, jwtkey.RequireToPluginFromCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*common.PublicKey, expectErr string) {
		actualOut, err := jwtkey.ToPluginFromCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { jwtkey.RequireToPluginFromCommonProtos(in) })
	}

	assertOK(t, []*common.PublicKey{commonGood}, []*plugintypes.JWTKey{pluginGood})
	assertFail(t, []*common.PublicKey{commonNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToPluginFromAPIProto(t *testing.T) {
	assertOK := func(t *testing.T, in *apitypes.JWTKey, expectOut *plugintypes.JWTKey) {
		actualOut, err := jwtkey.ToPluginFromAPIProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}
	assertFail := func(t *testing.T, in *apitypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToPluginFromAPIProto(in)
		spiretest.AssertErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, apiGood, pluginGood)
	assertFail(t, apiNoKeyID, "missing key ID for JWT key")
	assertFail(t, apiNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, apiBadPublicKey, `failed to unmarshal public key for JWT key "ID": `)
	assertOK(t, apiNoExpiresAt, pluginNoExpiresAt)
	assertOK(t, nil, nil)
}

func TestToPluginFromAPIProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*apitypes.JWTKey, expectOut []*plugintypes.JWTKey) {
		actualOut, err := jwtkey.ToPluginFromAPIProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in []*apitypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToPluginFromAPIProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, []*apitypes.JWTKey{apiGood}, []*plugintypes.JWTKey{pluginGood})
	assertFail(t, []*apitypes.JWTKey{apiNoKeyID}, "missing key ID for JWT key")
	assertOK(t, nil, nil)
}

func TestToAPIProto(t *testing.T) {
	assertOK := func(t *testing.T, in jwtkey.JWTKey, expectOut *apitypes.JWTKey) {
		actualOut, err := jwtkey.ToAPIProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in jwtkey.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToAPIProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, jwtKeyGood, apiGood)
	assertFail(t, jwtKeyNoKeyID, "missing key ID for JWT key")
	assertFail(t, jwtKeyNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, jwtKeyBadPublicKey, `failed to marshal public key for JWT key "ID": `)
	assertOK(t, jwtKeyNoExpiresAt, apiNoExpiresAt)
}

func TestToAPIFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.JWTKey, expectOut *apitypes.JWTKey) {
		actualOut, err := jwtkey.ToAPIFromPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in *plugintypes.JWTKey, expectErr string) {
		actualOut, err := jwtkey.ToAPIFromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, pluginGood, apiGood)
	assertFail(t, pluginNoKeyID, "missing key ID for JWT key")
	assertFail(t, pluginNoPublicKey, `missing public key for JWT key "ID"`)
	assertFail(t, pluginBadPublicKey, `failed to unmarshal public key for JWT key "ID": `)
	assertOK(t, pluginNoExpiresAt, apiNoExpiresAt)
	assertOK(t, nil, nil)
}

func assertJWTKeysEqual(t *testing.T, expected, actual []jwtkey.JWTKey) {
	assert.Empty(t, cmp.Diff(expected, actual))
}

func assertJWTKeyEqual(t *testing.T, expected, actual jwtkey.JWTKey) {
	assert.Empty(t, cmp.Diff(expected, actual))
}
