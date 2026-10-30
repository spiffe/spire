package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus/hooks/test"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher/common"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"
)

// TestBundlePublisherJWKSMatchesKeysEndpoint checks that the JWKS published by
// the BundlePublisher plugins with jwt_keys_only is the document served by the
// keys endpoint of the provider with set_key_use for the same bundle, byte for
// byte once the indentation of the provider's response is removed.
func TestBundlePublisherJWKSMatchesKeysEndpoint(t *testing.T) {
	log, _ := test.NewNullLogger()

	ca, _, err := util.LoadCAFixture()
	require.NoError(t, err)

	type jwtAuthority struct {
		keyID     string
		publicKey crypto.PublicKey
	}
	jwtAuthorities := []jwtAuthority{
		{keyID: "rsa2048", publicKey: testkey.MustRSA2048().Public()},
		{keyID: "rsa4096", publicKey: testkey.MustRSA4096().Public()},
		{keyID: "ec256", publicKey: testkey.MustEC256().Public()},
		{keyID: "ec384", publicKey: testkey.MustEC384().Public()},
	}

	pluginBundle := &plugintypes.Bundle{
		TrustDomain:     "domain.test",
		X509Authorities: []*plugintypes.X509Certificate{{Asn1: ca.Raw}},
		RefreshHint:     60,
		SequenceNumber:  42,
	}
	apiBundle := &apitypes.Bundle{
		TrustDomain:     "domain.test",
		X509Authorities: []*apitypes.X509Certificate{{Asn1: ca.Raw}},
		RefreshHint:     60,
		SequenceNumber:  42,
	}
	for _, jwtAuthority := range jwtAuthorities {
		pkix, err := x509.MarshalPKIXPublicKey(jwtAuthority.publicKey)
		require.NoError(t, err)
		pluginBundle.JwtAuthorities = append(pluginBundle.JwtAuthorities, &plugintypes.JWTKey{
			KeyId:     jwtAuthority.keyID,
			PublicKey: pkix,
		})
		apiBundle.JwtAuthorities = append(apiBundle.JwtAuthorities, &apitypes.JWTKey{
			KeyId:     jwtAuthority.keyID,
			PublicKey: pkix,
		})
	}

	// The provider gets the bundle from the server API source.
	source := &ServerAPISource{
		log:   log,
		clock: clock.NewMock(),
	}
	source.parseBundle(apiBundle)

	h, err := NewHandler(log, domainAllowlist(t, "domain.test"), source, false, true, nil, nil, "")
	require.NoError(t, err)

	r, err := http.NewRequest("GET", "https://domain.test/keys", nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	served := new(bytes.Buffer)
	require.NoError(t, json.Compact(served, w.Body.Bytes()))

	published, err := common.JWTKeysJWKS(pluginBundle)
	require.NoError(t, err)

	require.Equal(t, served.String(), string(published))
}
