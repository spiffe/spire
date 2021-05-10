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

func (fakeKeyManager) Single() (keymanager.SingleKeyManager, bool) {
	return fakeSingleKeyManager{}, true
}

func (fakeKeyManager) Multi() (keymanager.MultiKeyManager, bool) {
	return fakeMultiKeyManager{}, true
}

type fakeSingleKeyManager struct{}

func (fakeSingleKeyManager) Name() string { return "" }

func (fakeSingleKeyManager) Type() string { return "" }

func (fakeSingleKeyManager) GenerateKey(ctx context.Context) (crypto.Signer, error) {
	return fakeKey{}, nil
}

func (fakeSingleKeyManager) GetKey(ctx context.Context) (crypto.Signer, error) {
	return fakeKey{}, nil
}

func (fakeSingleKeyManager) SetKey(ctx context.Context, key crypto.Signer) error {
	return nil
}

type fakeMultiKeyManager struct{}

func (fakeMultiKeyManager) Name() string { return "" }

func (fakeMultiKeyManager) Type() string { return "" }

func (fakeMultiKeyManager) GenerateKey(ctx context.Context, id string, keyType keymanager.KeyType) (_ keymanager.Key, err error) {
	return fakeKey{}, nil
}

func (fakeMultiKeyManager) GetKey(ctx context.Context, id string) (_ keymanager.Key, err error) {
	return fakeKey{}, nil
}

func (fakeMultiKeyManager) GetKeys(ctx context.Context) (_ []keymanager.Key, err error) {
	return []keymanager.Key{fakeKey{}}, nil
}

type fakeKey struct{}

func (fakeKey) ID() string { return "" }

func (fakeKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (fakeKey) Public() crypto.PublicKey { return nil }

func TestWithMetrics(t *testing.T) {
	m := fakemetrics.New()
	w := WithMetrics(fakeKeyManager{}, m)

	single, ok := w.Single()
	require.True(t, ok)
	multi, ok := w.Multi()
	require.True(t, ok)

	for _, tt := range []struct {
		key  string
		call func() error
	}{
		{
			key: "agent_key_manager.generate_key_pair",
			call: func() error {
				_, err := single.GenerateKey(context.Background())
				return err
			},
		},
		{
			key: "agent_key_manager.fetch_private_key",
			call: func() error {
				_, err := single.GetKey(context.Background())
				return err
			},
		},
		{
			key: "agent_key_manager.store_private_key",
			call: func() error {
				return single.SetKey(context.Background(), nil)
			},
		},
		{
			key: "agent_key_manager.generate_key",
			call: func() error {
				_, err := multi.GenerateKey(context.Background(), "", keymanager.ECP256)
				return err
			},
		},
		{
			key: "agent_key_manager.get_key",
			call: func() error {
				_, err := multi.GetKey(context.Background(), "")
				return err
			},
		},
		{
			key: "agent_key_manager.get_keys",
			call: func() error {
				_, err := multi.GetKeys(context.Background())
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
