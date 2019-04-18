package workload

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/gogo/protobuf/proto"
	"github.com/spiffe/spire/proto/spire/api/workload"
	"github.com/spiffe/spire/test/fakes/fakeworkloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// No tests rely on timing, however, due to the nature of the X509Client
	// and StreamX509SVID calls the only way to observe externally that
	// something is broken is through failure to receive on channels. Using the
	// following timeout to prevent having to wait for the default go test
	// timeout (10 minutes) if this happens. The timeout should be large enough
	// by a comfortable margin to accomodate for slower running platforms, like
	// Travis CI.
	testTimeout = time.Minute
)

var (
	responseA = &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{SpiffeId: "A"}}}
	responseB = &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{SpiffeId: "B"}}}
	responseC = &workload.X509SVIDResponse{Svids: []*workload.X509SVID{{SpiffeId: "C"}}}

	errFake = errors.New("fake error")
)

func TestX509ClientProvidesConfigDefaults(t *testing.T) {
	client := newX509Client(nil)
	client.hooks.streamX509SVID = func(_ context.Context, c *X509ClientConfig, _ chan<- *workload.X509SVIDResponse) error {
		assert.Nil(t, c.Addr)
		assert.False(t, c.FailOnError)
		assert.Equal(t, defaultTimeout, c.Timeout)
		assert.Equal(t, defaultBackoffCap, c.BackoffCap)
		assert.Nil(t, c.Log)
		assert.NotNil(t, c.Clock)
		return nil
	}
	require.NoError(t, client.Start())
}

func TestX509ClientStartReturnsStreamingError(t *testing.T) {
	client := newX509Client(nil)
	client.hooks.streamX509SVID = func(context.Context, *X509ClientConfig, chan<- *workload.X509SVIDResponse) error {
		return errors.New("streaming error")
	}
	require.EqualError(t, client.Start(), "streaming error")
}

func TestX509ClientStartFailsIfAlreadyStarted(t *testing.T) {
	client := newX509Client(nil)
	client.hooks.streamX509SVID = func(ctx context.Context, _ *X509ClientConfig, _ chan<- *workload.X509SVIDResponse) error {
		<-ctx.Done()
		return ctx.Err()
	}
	defer client.Stop()

	errs := make(chan error, 2)
	go func() {
		errs <- client.Start()
	}()
	go func() {
		errs <- client.Start()
	}()

	timer := time.NewTimer(testTimeout)
	defer timer.Stop()

	// First call should fail because the client has already started
	select {
	case err := <-errs:
		assert.EqualError(t, err, "already started")
	case <-timer.C:
		require.FailNow(t, "timed out waiting for client.Start() to return")
	}

	client.Stop()

	// Second call should return normally
	select {
	case err := <-errs:
		assert.NoError(t, err)
	case <-timer.C:
		require.FailNow(t, "timed out waiting for client.Start() to return")
	}
}

func TestX509ClientUnreadUpdatesDiscarded(t *testing.T) {
	client := newX509Client(nil)
	client.hooks.streamX509SVID = func(ctx context.Context, _ *X509ClientConfig, out chan<- *workload.X509SVIDResponse) error {
		select {
		case out <- responseA:
		case <-ctx.Done():
			return errors.New("unexpected cancellation sending response A")
		}
		select {
		case out <- responseB:
		case <-ctx.Done():
			return errors.New("unexpected cancellation sending response B")
		}
		return nil
	}
	require.NoError(t, client.Start())

	// This keeps us from waiting for the full go test timeout if something is
	// wrong. It shouldn't be hit when tests are passing.
	timer := time.NewTimer(testTimeout)
	defer timer.Stop()
	select {
	case update := <-client.UpdateChan():
		assertResponseEqual(t, responseB, update)
	case <-timer.C:
		require.FailNow(t, "timed out waiting for update")
	}
}

func TestX509ClientCurrentSVID(t *testing.T) {
	client := newX509Client(nil)

	svid, err := client.CurrentSVID()
	assert.EqualError(t, err, "no SVID received yet")
	assert.Nil(t, svid)

	client.hooks.streamX509SVID = func(ctx context.Context, _ *X509ClientConfig, out chan<- *workload.X509SVIDResponse) error {
		select {
		case out <- responseA:
		case <-ctx.Done():
			return errors.New("unexpected cancellation sending response A")
		}
		return nil
	}
	require.NoError(t, client.Start())

	svid, err = client.CurrentSVID()
	assert.NoError(t, err)
	assertResponseEqual(t, responseA, svid)
}

func TestStreamX509SVIDBackoffOnFetchFailure(t *testing.T) {
	testStreamX509SVIDBackoff(t, &net.UnixAddr{
		Net:  "unix",
		Name: "this/path/does/not/exist",
	})
}

func TestStreamX509SVIDBackoffOnRecvFailure(t *testing.T) {
	w := fakeworkloadapi.New(t, fakeworkloadapi.FetchX509SVIDErrorAlways(errFake))
	defer w.Close()

	testStreamX509SVIDBackoff(t, w.Addr())
}

func testStreamX509SVIDBackoff(t *testing.T, addr net.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	mockClock := newMockClock()

	errch := make(chan error, 1)
	go func() {
		errch <- StreamX509SVID(ctx, &X509ClientConfig{
			Addr:       addr,
			Clock:      mockClock,
			BackoffCap: 3 * time.Second,
			Timeout:    13 * time.Second,
		}, nil)
	}()

	waitForTimer := func(expected float64) {
		duration, ok := mockClock.WaitUntilTimerStarted(ctx.Done())
		require.True(t, ok, "timed out waiting for timer to get created")
		assert.Equal(t, time.Duration(float64(time.Second)*expected), duration)
		mockClock.Add(duration)
	}

	// starts at one second
	waitForTimer(1.0)

	// grows geometrically
	waitForTimer(1.5)
	waitForTimer(2.25)

	// cap has been hit
	waitForTimer(3.0)

	// cap still hit
	waitForTimer(3.0)

	// remainder between timeout and elapsed
	waitForTimer(2.25)

	// StreamX509SVID should fail with "timeout exceeded"
	assert.EqualError(t, <-errch, "timeout exceeded")
}

func TestStreamX509SVIDFailsOnInvalidArgument(t *testing.T) {
	w := fakeworkloadapi.New(t, fakeworkloadapi.FetchX509SVIDErrorOnce(
		status.Error(codes.InvalidArgument, "invalid argument"),
	))
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	err := StreamX509SVID(ctx, &X509ClientConfig{
		Addr: w.Addr(),
	}, nil)

	s := status.Convert(err)
	assert.Equal(t, codes.InvalidArgument, s.Code())
	assert.Equal(t, "invalid argument", s.Message())
}

func TestStreamX509SVIDFailOnError(t *testing.T) {
	w := fakeworkloadapi.New(t, fakeworkloadapi.FetchX509SVIDErrorOnce(errFake))
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	err := StreamX509SVID(ctx, &X509ClientConfig{
		Addr:        w.Addr(),
		FailOnError: true,
	}, nil)

	s := status.Convert(err)
	assert.Equal(t, codes.Unknown, s.Code())
	assert.Equal(t, "fake error", s.Message())
}

func TestStreamX509SVIDWritesUpdatesToChannel(t *testing.T) {
	w := fakeworkloadapi.New(t, fakeworkloadapi.FetchX509SVIDResponses(responseA, responseB, responseC))
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	out := make(chan *workload.X509SVIDResponse)
	errch := make(chan error, 1)
	go func() {
		errch <- StreamX509SVID(ctx, &X509ClientConfig{
			Addr: w.Addr(),
		}, out)
	}()

	// Verify each response is sent on the out channel
	select {
	case response := <-out:
		assertResponseEqual(t, responseA, response)
	case <-ctx.Done():
		require.FailNow(t, "timed out waiting for response A")
	}
	select {
	case response := <-out:
		assertResponseEqual(t, responseB, response)
	case <-ctx.Done():
		require.FailNow(t, "timed out waiting for response B")
	}
	select {
	case response := <-out:
		assertResponseEqual(t, responseC, response)
	case <-ctx.Done():
		require.FailNow(t, "timed out waiting for response C")
	}

	cancel()
	assert.Equal(t, context.Canceled, <-errch)
}

type mockClock struct {
	*clock.Mock
	timerStarted chan time.Duration
}

func newMockClock() *mockClock {
	return &mockClock{
		Mock:         clock.NewMock(),
		timerStarted: make(chan time.Duration),
	}
}

func (c *mockClock) Timer(duration time.Duration) *clock.Timer {
	timer := c.Mock.Timer(duration)
	c.timerStarted <- duration
	return timer
}

func (c *mockClock) WaitUntilTimerStarted(done <-chan struct{}) (time.Duration, bool) {
	select {
	case <-done:
		return 0, false
	case duration := <-c.timerStarted:
		return duration, true
	}
}

func assertResponseEqual(t *testing.T, expected, actual *workload.X509SVIDResponse) {
	assert.True(t, proto.Equal(actual, expected), "expected response %+v; got %+v", expected, actual)
}
