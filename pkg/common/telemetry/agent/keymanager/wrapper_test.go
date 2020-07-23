package keymanager

import (
	"context"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeyManager struct{}

func (mockKeyManager) GenerateKeyPair(ctx context.Context, req *keymanager.GenerateKeyPairRequest) (*keymanager.GenerateKeyPairResponse, error) {
	return nil, nil
}

func (mockKeyManager) FetchPrivateKey(ctx context.Context, req *keymanager.FetchPrivateKeyRequest) (*keymanager.FetchPrivateKeyResponse, error) {
	return nil, nil
}

func (mockKeyManager) StorePrivateKey(ctx context.Context, req *keymanager.StorePrivateKeyRequest) (*keymanager.StorePrivateKeyResponse, error) {
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
			key: "agent_key_manager.generate_key_pair",
			call: func() error {
				_, err := w.GenerateKeyPair(context.Background(), nil)
				return err
			},
		},
		{
			key: "agent_key_manager.fetch_private_key",
			call: func() error {
				_, err := w.FetchPrivateKey(context.Background(), nil)
				return err
			},
		},
		{
			key: "agent_key_manager.store_private_key",
			call: func() error {
				_, err := w.StorePrivateKey(context.Background(), nil)
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
