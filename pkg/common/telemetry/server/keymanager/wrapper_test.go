package keymanager

import (
	"context"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/telemetry"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/server/keymanager/v0"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeyManager struct{}

func (mockKeyManager) GenerateKey(ctx context.Context, req *keymanagerv0.GenerateKeyRequest) (*keymanagerv0.GenerateKeyResponse, error) {
	return nil, nil
}

func (mockKeyManager) GetPublicKey(ctx context.Context, req *keymanagerv0.GetPublicKeyRequest) (*keymanagerv0.GetPublicKeyResponse, error) {
	return nil, nil
}

func (mockKeyManager) GetPublicKeys(ctx context.Context, req *keymanagerv0.GetPublicKeysRequest) (*keymanagerv0.GetPublicKeysResponse, error) {
	return nil, nil
}

func (mockKeyManager) SignData(ctx context.Context, req *keymanagerv0.SignDataRequest) (*keymanagerv0.SignDataResponse, error) {
	return nil, nil
}

func TestWithMetrics(t *testing.T) {
	var km mockKeyManager
	m := fakemetrics.New()
	w := WithMetrics(km, m)
	for _, tt := range []struct {
		key  string
		call func() error
	}{
		{
			key: "server_key_manager.generate_key",
			call: func() error {
				_, err := w.GenerateKey(context.Background(), nil)
				return err
			},
		},
		{
			key: "server_key_manager.get_public_key",
			call: func() error {
				_, err := w.GetPublicKey(context.Background(), nil)
				return err
			},
		},
		{
			key: "server_key_manager.get_public_keys",
			call: func() error {
				_, err := w.GetPublicKeys(context.Background(), nil)
				return err
			},
		},
		{
			key: "server_key_manager.sign_data",
			call: func() error {
				_, err := w.SignData(context.Background(), nil)
				return err
			},
		},
	} {
		tt := tt
		m.Reset()
		require.NoError(t, tt.call())
		key := strings.Split(tt.key, ".")
		expectedMetrics := []fakemetrics.MetricItem{{
			Type:   fakemetrics.IncrCounterWithLabelsType,
			Key:    key,
			Val:    1,
			Labels: []telemetry.Label{{Name: "status", Value: "OK"}},
		},
			{
				Type:   fakemetrics.MeasureSinceWithLabelsType,
				Key:    append(key, "elapsed_time"),
				Labels: []telemetry.Label{{Name: "status", Value: "OK"}},
			},
		}
		assert.Equal(t, expectedMetrics, m.AllMetrics())
	}
}
