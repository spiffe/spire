package keymanager

import (
	"context"
	"crypto"
	"io"
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
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
	w := WithMetrics(fakeKeyManager{}, m)
	for _, tt := range []struct {
		key  string
		call func(*testing.T)
	}{
		{
			key: "server_key_manager.generate_key",
			call: func(t *testing.T) {
				_, err := w.GenerateKey(context.Background(), "", keymanager.ECP256)
				require.NoError(t, err)
			},
		},
		{
			key: "server_key_manager.get_public_key",
			call: func(t *testing.T) {
				_, err := w.GetKey(context.Background(), "")
				require.NoError(t, err)
			},
		},
		{
			key: "server_key_manager.get_public_keys",
			call: func(t *testing.T) {
				_, err := w.GetKeys(context.Background())
				require.NoError(t, err)
			},
		},
		{
			key: "server_key_manager.sign_data",
			call: func(t *testing.T) {
				key, err := w.GetKey(context.Background(), "")
				require.NoError(t, err)
				m.Reset()
				_, err = key.Sign(nil, nil, nil)
				require.NoError(t, err)
			},
		},
	} {
		tt := tt
		m.Reset()
		tt.call(t)

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
