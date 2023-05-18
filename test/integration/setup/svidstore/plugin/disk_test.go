//go:build !windows
// +build !windows

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPutDeleteX509SVID(t *testing.T) {
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
	require.NoError(t, err)

	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	require.True(t, ssClient.IsInitialized())

	svid := &svidstorev1.X509SVID{
		SpiffeID:   "spiffe://example.org/workload",
		PrivateKey: keyData,
		CertChain:  [][]byte{{1, 2, 3}},
		Bundle:     [][]byte{},
		ExpiresAt:  time.Now().Unix(),
	}

	// PutX509SVID writes the SVID on disk
	_, err = ssClient.PutX509SVID(ctx, &svidstorev1.PutX509SVIDRequest{
		Svid:     svid,
		Metadata: []string{`name:workload`},
	})
	require.NoError(t, err)

	data, err := os.ReadFile("/tmp/svids")
	require.NoError(t, err)

	storedSVIDS := map[string]*svidstorev1.X509SVID{}
	err = json.Unmarshal(data, &storedSVIDS)
	require.NoError(t, err)
	require.Len(t, storedSVIDS, 1)
	spiretest.RequireProtoEqual(t, svid, storedSVIDS["workload"])

	// DeleteX509SVID deletes the SVID from disk
	_, err = ssClient.DeleteX509SVID(ctx, &svidstorev1.DeleteX509SVIDRequest{
		Metadata: []string{`name:workload`},
	})
	assert.NoError(t, err)

	data, err = os.ReadFile("/tmp/svids")
	require.NoError(t, err)
	require.Equal(t, "{}", string(data))
}
