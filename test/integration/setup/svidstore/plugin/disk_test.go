package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	plugin := new(Plugin)
	ssClient := new(svidstorev1.SVIDStorePluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: svidstorev1.SVIDStorePluginServer(plugin),
		PluginClient: ssClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})

	ctx := context.Background()

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  `svids_path = "/tmp/svids"`,
	})
	assert.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	require.True(t, ssClient.IsInitialized())

	_, err = ssClient.PutX509SVID(ctx, &svidstorev1.PutX509SVIDRequest{
		Svid: &svidstorev1.X509SVID{
			SpiffeID:   "spiffe://example.org/workload",
			PrivateKey: keyData,
			CertChain:  [][]byte{{1, 2, 3}},
			Bundle:     [][]byte{},
			ExpiresAt:  time.Now().Unix(),
		},
		Metadata: []string{`name:workload`},
	})
	assert.NoError(t, err)
	_, err = ssClient.DeleteX509SVID(ctx, &svidstorev1.DeleteX509SVIDRequest{
		Metadata: []string{`name:workload`},
	})
	assert.NoError(t, err)
}
