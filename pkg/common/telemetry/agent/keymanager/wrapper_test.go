package keymanager

import (
	"context"
	"crypto"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeKeyManager struct{}

func (fakeKeyManager) GenerateKey(ctx context.Context) (crypto.Signer, error) {
	return nil, nil
}

func (fakeKeyManager) GetKey(ctx context.Context) (crypto.Signer, error) {
	return nil, nil
}

func (fakeKeyManager) SetKey(ctx context.Context, key crypto.Signer) error {
	return nil
}

func TestWithMetrics(t *testing.T) {
	m := fakemetrics.New()
	w := WithMetrics(fakeKeyManager{}, m)
	for _, tt := range []struct {
		key  string
		call func() error
	}{
		{
			key: "agent_key_manager.generate_key_pair",
			call: func() error {
				_, err := w.GenerateKey(context.Background())
				return err
			},
		},
		{
			key: "agent_key_manager.fetch_private_key",
			call: func() error {
				_, err := w.GetKey(context.Background())
				return err
			},
		},
		{
			key: "agent_key_manager.store_private_key",
			call: func() error {
				return w.SetKey(context.Background(), nil)
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
