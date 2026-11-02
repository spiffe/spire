package nodeattestor_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/stretchr/testify/require"
)

// hangingServerStream never responds: it waits for the context to be done,
// mimicking a silently dead connection to the server.
type hangingServerStream struct{}

func (hangingServerStream) SendAttestationData(ctx context.Context, _ nodeattestor.AttestationData) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (hangingServerStream) SendChallengeResponse(ctx context.Context, _ []byte) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWithTimeoutAppliesDeadline(t *testing.T) {
	att := loadV1Plugin(t, &fakeV1Plugin{payload: []byte("payload")})
	err := nodeattestor.WithTimeout(att, 50*time.Millisecond).Attest(context.Background(), hangingServerStream{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestWithTimeoutDisabled(t *testing.T) {
	att := loadV1Plugin(t, &fakeV1Plugin{payload: []byte("payload")})
	require.Same(t, att, nodeattestor.WithTimeout(att, 0))
	require.Same(t, att, nodeattestor.WithTimeout(att, -time.Second))
}

func TestWithTimeoutForwardsPluginInfo(t *testing.T) {
	att := loadV1Plugin(t, &fakeV1Plugin{payload: []byte("payload")})
	require.Equal(t, att.Name(), nodeattestor.WithTimeout(att, time.Minute).Name())
}
