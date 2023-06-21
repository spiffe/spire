package keymanager

import (
	"context"
	"crypto"
	"io"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeKeyManager struct{}

func (fakeKeyManager) Name() string { return "" }

func (fakeKeyManager) Type() string { return "" }

func (fakeKeyManager) GenerateKey(context.Context, string, keymanager.KeyType) (_ keymanager.Key, err error) {
	return fakeKey{}, nil
}

func (fakeKeyManager) GetKey(context.Context, string) (_ keymanager.Key, err error) {
	return fakeKey{}, nil
}

func (fakeKeyManager) GetKeys(context.Context) (_ []keymanager.Key, err error) {
	return []keymanager.Key{fakeKey{}}, nil
}

type fakeKey struct{}

func (fakeKey) ID() string { return "" }

func (fakeKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (fakeKey) Public() crypto.PublicKey { return nil }

func TestWithMetrics(t *testing.T) {
	m := fakemetrics.New()
	km := WithMetrics(fakeKeyManager{}, m)

	for _, tt := range []struct {
		key  string
		call func() error
	}{
		{
			key: "agent_key_manager.generate_key",
			call: func() error {
				_, err := km.GenerateKey(context.Background(), "", keymanager.ECP256)
				return err
			},
		},
		{
			key: "agent_key_manager.get_key",
			call: func() error {
				_, err := km.GetKey(context.Background(), "")
				return err
			},
		},
		{
			key: "agent_key_manager.get_keys",
			call: func() error {
				_, err := km.GetKeys(context.Background())
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
