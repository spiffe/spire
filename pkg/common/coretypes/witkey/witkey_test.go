package witkey_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/witkey"
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
	witKeyGood         = witkey.WITKey{ID: "ID", PublicKey: publicKey, ExpiresAt: expiresAt}
	witKeyTaintedGood  = witkey.WITKey{ID: "ID", PublicKey: publicKey, ExpiresAt: expiresAt, Tainted: true}
	witKeyNoKeyID      = witkey.WITKey{PublicKey: publicKey, ExpiresAt: expiresAt}
	witKeyNoPublicKey  = witkey.WITKey{ID: "ID", ExpiresAt: expiresAt}
	witKeyBadPublicKey = witkey.WITKey{ID: "ID", PublicKey: junk, ExpiresAt: expiresAt}
	witKeyNoExpiresAt  = witkey.WITKey{ID: "ID", PublicKey: publicKey}
	pluginGood         = &plugintypes.WITKey{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	pluginTaintedGood  = &plugintypes.WITKey{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix(), Tainted: true}
	pluginNoKeyID      = &plugintypes.WITKey{PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	pluginNoPublicKey  = &plugintypes.WITKey{KeyId: "ID", ExpiresAt: expiresAt.Unix()}
	pluginBadPublicKey = &plugintypes.WITKey{KeyId: "ID", PublicKey: junk, ExpiresAt: expiresAt.Unix()}
	pluginNoExpiresAt  = &plugintypes.WITKey{KeyId: "ID", PublicKey: pkixBytes}
	commonGood         = &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes, NotAfter: expiresAt.Unix()}
	commonTaintedGood  = &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes, NotAfter: expiresAt.Unix(), TaintedKey: true}
	commonNoKeyID      = &common.PublicKey{PkixBytes: pkixBytes, NotAfter: expiresAt.Unix()}
	commonNoPublicKey  = &common.PublicKey{Kid: "ID", NotAfter: expiresAt.Unix()}
	commonBadPublicKey = &common.PublicKey{Kid: "ID", PkixBytes: junk, NotAfter: expiresAt.Unix()}
	commonNoExpiresAt  = &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes}
	apiGood            = &apitypes.WITKey{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	apiTaintedGood     = &apitypes.WITKey{KeyId: "ID", PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix(), Tainted: true}
	apiNoKeyID         = &apitypes.WITKey{PublicKey: pkixBytes, ExpiresAt: expiresAt.Unix()}
	apiNoPublicKey     = &apitypes.WITKey{KeyId: "ID", ExpiresAt: expiresAt.Unix()}
	apiBadPublicKey    = &apitypes.WITKey{KeyId: "ID", PublicKey: junk, ExpiresAt: expiresAt.Unix()}
	apiNoExpiresAt     = &apitypes.WITKey{KeyId: "ID", PublicKey: pkixBytes}
)

func TestFromCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in *common.PublicKey, expectOut witkey.WITKey) {
		actualOut, err := witkey.FromCommonProto(in)
		require.NoError(t, err)
		assertWITKeyEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertWITKeyEqual(t, expectOut, witkey.RequireFromCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in *common.PublicKey, expectErr string) {
		actualOut, err := witkey.FromCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireFromCommonProto(in) })
	}

	assertOK(t, commonGood, witKeyGood)
	assertOK(t, commonTaintedGood, witKeyTaintedGood)
	assertFail(t, commonNoKeyID, "missing key ID for WIT key")
	assertFail(t, commonNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, commonBadPublicKey, `failed to unmarshal public key for WIT key "ID": `)
	assertOK(t, commonNoExpiresAt, witKeyNoExpiresAt)
}

func TestFromCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*common.PublicKey, expectOut []witkey.WITKey) {
		actualOut, err := witkey.FromCommonProtos(in)
		require.NoError(t, err)
		assertWITKeysEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertWITKeysEqual(t, expectOut, witkey.RequireFromCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*common.PublicKey, expectErr string) {
		actualOut, err := witkey.FromCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Nil(t, actualOut)
		assert.Panics(t, func() { witkey.RequireFromCommonProtos(in) })
	}

	assertOK(t, []*common.PublicKey{commonGood, commonTaintedGood},
		[]witkey.WITKey{witKeyGood, witKeyTaintedGood})
	assertFail(t, []*common.PublicKey{commonNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestToCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in witkey.WITKey, expectOut *common.PublicKey) {
		actualOut, err := witkey.ToCommonProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, witkey.RequireToCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in witkey.WITKey, expectErr string) {
		actualOut, err := witkey.ToCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToCommonProto(in) })
	}

	assertOK(t, witKeyGood, commonGood)
	assertOK(t, witKeyTaintedGood, commonTaintedGood)
	assertFail(t, witKeyNoKeyID, "missing key ID for WIT key")
	assertFail(t, witKeyNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, witKeyBadPublicKey, `failed to marshal public key for WIT key "ID": `)
	assertOK(t, witKeyNoExpiresAt, commonNoExpiresAt)
}

func TestToCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []witkey.WITKey, expectOut []*common.PublicKey) {
		actualOut, err := witkey.ToCommonProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, witkey.RequireToCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []witkey.WITKey, expectErr string) {
		actualOut, err := witkey.ToCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToCommonProtos(in) })
	}

	assertOK(t, []witkey.WITKey{witKeyGood, witKeyTaintedGood},
		[]*common.PublicKey{commonGood, commonTaintedGood})
	assertFail(t, []witkey.WITKey{witKeyNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.WITKey, expectOut witkey.WITKey) {
		actualOut, err := witkey.FromPluginProto(in)
		require.NoError(t, err)
		assertWITKeyEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertWITKeyEqual(t, expectOut, witkey.RequireFromPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *plugintypes.WITKey, expectErr string) {
		actualOut, err := witkey.FromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireFromPluginProto(in) })
	}

	assertOK(t, pluginGood, witKeyGood)
	assertOK(t, pluginTaintedGood, witKeyTaintedGood)
	assertFail(t, pluginNoKeyID, "missing key ID for WIT key")
	assertFail(t, pluginNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, pluginBadPublicKey, `failed to unmarshal public key for WIT key "ID": `)
	assertOK(t, pluginNoExpiresAt, witKeyNoExpiresAt)
}

func TestFromPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*plugintypes.WITKey, expectOut []witkey.WITKey) {
		actualOut, err := witkey.FromPluginProtos(in)
		require.NoError(t, err)
		assertWITKeysEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { assertWITKeysEqual(t, expectOut, witkey.RequireFromPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*plugintypes.WITKey, expectErr string) {
		actualOut, err := witkey.FromPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Nil(t, actualOut)
		assert.Panics(t, func() { witkey.RequireFromPluginProtos(in) })
	}

	assertOK(t, []*plugintypes.WITKey{pluginGood, pluginTaintedGood},
		[]witkey.WITKey{witKeyGood, witKeyTaintedGood})
	assertFail(t, []*plugintypes.WITKey{pluginNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestToPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in witkey.WITKey, expectOut *plugintypes.WITKey) {
		actualOut, err := witkey.ToPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, witkey.RequireToPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in witkey.WITKey, expectErr string) {
		actualOut, err := witkey.ToPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToPluginProto(in) })
	}

	assertOK(t, witKeyGood, pluginGood)
	assertOK(t, witKeyTaintedGood, pluginTaintedGood)
	assertFail(t, witKeyNoKeyID, "missing key ID for WIT key")
	assertFail(t, witKeyNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, witKeyBadPublicKey, `failed to marshal public key for WIT key "ID": `)
	assertOK(t, witKeyNoExpiresAt, pluginNoExpiresAt)
}

func TestToPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []witkey.WITKey, expectOut []*plugintypes.WITKey) {
		actualOut, err := witkey.ToPluginProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, witkey.RequireToPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []witkey.WITKey, expectErr string) {
		actualOut, err := witkey.ToPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToPluginProtos(in) })
	}

	assertOK(t, []witkey.WITKey{witKeyGood, witKeyTaintedGood},
		[]*plugintypes.WITKey{pluginGood, pluginTaintedGood})
	assertFail(t, []witkey.WITKey{witKeyNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestToCommonFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.WITKey, expectOut *common.PublicKey) {
		actualOut, err := witkey.ToCommonFromPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, witkey.RequireToCommonFromPluginProto(in)) })
	}

	assertFail := func(t *testing.T, in *plugintypes.WITKey, expectErr string) {
		actualOut, err := witkey.ToCommonFromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToCommonFromPluginProto(in) })
	}

	assertOK(t, pluginGood, commonGood)
	assertOK(t, pluginTaintedGood, commonTaintedGood)
	assertFail(t, pluginNoKeyID, "missing key ID for WIT key")
	assertFail(t, pluginNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, pluginBadPublicKey, `failed to unmarshal public key for WIT key "ID": `)
	assertOK(t, pluginNoExpiresAt, commonNoExpiresAt)
}

func TestToCommonFromPluginProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*plugintypes.WITKey, expectOut []*common.PublicKey) {
		actualOut, err := witkey.ToCommonFromPluginProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, witkey.RequireToCommonFromPluginProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*plugintypes.WITKey, expectErr string) {
		actualOut, err := witkey.ToCommonFromPluginProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToCommonFromPluginProtos(in) })
	}

	assertOK(t, []*plugintypes.WITKey{pluginGood, pluginTaintedGood},
		[]*common.PublicKey{commonGood, commonTaintedGood})
	assertFail(t, []*plugintypes.WITKey{pluginNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestToPluginFromCommonProto(t *testing.T) {
	assertOK := func(t *testing.T, in *common.PublicKey, expectOut *plugintypes.WITKey) {
		actualOut, err := witkey.ToPluginFromCommonProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoEqual(t, expectOut, witkey.RequireToPluginFromCommonProto(in)) })
	}

	assertFail := func(t *testing.T, in *common.PublicKey, expectErr string) {
		actualOut, err := witkey.ToPluginFromCommonProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToPluginFromCommonProto(in) })
	}

	assertOK(t, commonGood, pluginGood)
	assertOK(t, commonTaintedGood, pluginTaintedGood)
	assertFail(t, commonNoKeyID, "missing key ID for WIT key")
	assertFail(t, commonNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, commonBadPublicKey, `failed to unmarshal public key for WIT key "ID": `)
	assertOK(t, commonNoExpiresAt, pluginNoExpiresAt)
}

func TestToPluginFromCommonProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*common.PublicKey, expectOut []*plugintypes.WITKey) {
		actualOut, err := witkey.ToPluginFromCommonProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
		assert.NotPanics(t, func() { spiretest.AssertProtoListEqual(t, expectOut, witkey.RequireToPluginFromCommonProtos(in)) })
	}

	assertFail := func(t *testing.T, in []*common.PublicKey, expectErr string) {
		actualOut, err := witkey.ToPluginFromCommonProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
		assert.Panics(t, func() { witkey.RequireToPluginFromCommonProtos(in) })
	}

	assertOK(t, []*common.PublicKey{commonGood, commonTaintedGood},
		[]*plugintypes.WITKey{pluginGood, pluginTaintedGood})
	assertFail(t, []*common.PublicKey{commonNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestToPluginFromAPIProto(t *testing.T) {
	assertOK := func(t *testing.T, in *apitypes.WITKey, expectOut *plugintypes.WITKey) {
		actualOut, err := witkey.ToPluginFromAPIProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}
	assertFail := func(t *testing.T, in *apitypes.WITKey, expectErr string) {
		actualOut, err := witkey.ToPluginFromAPIProto(in)
		spiretest.AssertErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, apiGood, pluginGood)
	assertOK(t, apiTaintedGood, pluginTaintedGood)
	assertFail(t, apiNoKeyID, "missing key ID for WIT key")
	assertFail(t, apiNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, apiBadPublicKey, `failed to unmarshal public key for WIT key "ID": `)
	assertOK(t, apiNoExpiresAt, pluginNoExpiresAt)
	assertOK(t, nil, nil)
}

func TestToPluginFromAPIProtos(t *testing.T) {
	assertOK := func(t *testing.T, in []*apitypes.WITKey, expectOut []*plugintypes.WITKey) {
		actualOut, err := witkey.ToPluginFromAPIProtos(in)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in []*apitypes.WITKey, expectErr string) {
		actualOut, err := witkey.ToPluginFromAPIProtos(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, []*apitypes.WITKey{apiGood, apiTaintedGood},
		[]*plugintypes.WITKey{pluginGood, pluginTaintedGood})
	assertFail(t, []*apitypes.WITKey{apiNoKeyID}, "missing key ID for WIT key")
	assertOK(t, nil, nil)
}

func TestToAPIProto(t *testing.T) {
	assertOK := func(t *testing.T, in witkey.WITKey, expectOut *apitypes.WITKey) {
		actualOut, err := witkey.ToAPIProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in witkey.WITKey, expectErr string) {
		actualOut, err := witkey.ToAPIProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, witKeyGood, apiGood)
	assertOK(t, witKeyTaintedGood, apiTaintedGood)
	assertFail(t, witKeyNoKeyID, "missing key ID for WIT key")
	assertFail(t, witKeyNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, witKeyBadPublicKey, `failed to marshal public key for WIT key "ID": `)
	assertOK(t, witKeyNoExpiresAt, apiNoExpiresAt)
}

func TestToAPIFromPluginProto(t *testing.T) {
	assertOK := func(t *testing.T, in *plugintypes.WITKey, expectOut *apitypes.WITKey) {
		actualOut, err := witkey.ToAPIFromPluginProto(in)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, expectOut, actualOut)
	}

	assertFail := func(t *testing.T, in *plugintypes.WITKey, expectErr string) {
		actualOut, err := witkey.ToAPIFromPluginProto(in)
		spiretest.RequireErrorPrefix(t, err, expectErr)
		assert.Empty(t, actualOut)
	}

	assertOK(t, pluginGood, apiGood)
	assertOK(t, pluginTaintedGood, apiTaintedGood)
	assertFail(t, pluginNoKeyID, "missing key ID for WIT key")
	assertFail(t, pluginNoPublicKey, `missing public key for WIT key "ID"`)
	assertFail(t, pluginBadPublicKey, `failed to unmarshal public key for WIT key "ID": `)
	assertOK(t, pluginNoExpiresAt, apiNoExpiresAt)
	assertOK(t, nil, nil)
}

func assertWITKeysEqual(t *testing.T, expected, actual []witkey.WITKey) {
	assert.Empty(t, cmp.Diff(expected, actual))
}

func assertWITKeyEqual(t *testing.T, expected, actual witkey.WITKey) {
	assert.Empty(t, cmp.Diff(expected, actual))
}
