package akeylesskms

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
)

// Enable this test only if you have akeyless access key and id and running gateway in order to test it on real account
func _Test(t *testing.T) {
	plugin := new(Plugin)
	kmClient := new(keymanagerv1.KeyManagerPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	// Serve the plugin in the background with the configured plugin and
	// service servers. The servers will be cleaned up when the test finishes.
	// TODO: Remove the config service server and client if no configuration
	// is required.
	// TODO: Provide host service server implementations if required by the
	// plugin.
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: keymanagerv1.KeyManagerPluginServer(plugin),
		PluginClient: kmClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})

	ctx := context.Background()

	mapConfig := make(map[string]string)
	mapConfig["akeyless_access_key_id"] = "<>"
	mapConfig["akeyless_access_key"] = "<>"

	marshalledConfig, _ := json.Marshal(mapConfig)
	hclConfig := string(marshalledConfig)

	// TODO: Remove if no configuration is required.
	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  hclConfig,
	})
	require.NoError(t, err)

	require.True(t, kmClient.IsInitialized())
	spireKeyId := fmt.Sprintf("bundle-acme-foo-%v", time.Now().Unix())

	_, err = kmClient.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: spireKeyId,
		KeyType: keymanagerv1.KeyType_EC_P256})
	require.NoError(t, err)

	_, err = kmClient.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})
	require.NoError(t, err)
	out, err := kmClient.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{KeyId: spireKeyId})
	require.NoError(t, err)
	require.Equal(t, spireKeyId, out.PublicKey.Id)
	require.Equal(t, keymanagerv1.KeyType_EC_P256, out.PublicKey.Type)
	_, err = x509.ParsePKIXPublicKey(out.PublicKey.PkixData)
	require.NoError(t, err)
}
