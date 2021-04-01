package keymanager

import (
	"context"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/telemetry"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeyManager struct{}

func (mockKeyManager) GenerateKeyPair(ctx context.Context, req *keymanagerv0.GenerateKeyPairRequest) (*keymanagerv0.GenerateKeyPairResponse, error) {
	return nil, nil
}

func (mockKeyManager) FetchPrivateKey(ctx context.Context, req *keymanagerv0.FetchPrivateKeyRequest) (*keymanagerv0.FetchPrivateKeyResponse, error) {
	return nil, nil
}

func (mockKeyManager) StorePrivateKey(ctx context.Context, req *keymanagerv0.StorePrivateKeyRequest) (*keymanagerv0.StorePrivateKeyResponse, error) {
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
