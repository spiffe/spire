package endpoints

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func openLifecycleStream(t *testing.T, c streamTestClients, method string, caller int) func() {
	t.Helper()
	cancel, result := startStream(t, c, method, caller, 30*time.Second)
	select {
	case <-c.manager.started:
	case err := <-result:
		cancel()
		t.Fatalf("stream should have available capacity: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("stream admission did not settle")
	}
	select {
	case <-c.manager.subscriptions:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("admitted stream did not subscribe")
	}
	return func() {
		cancel()
		expectStreamError(t, result, codes.Canceled)
		waitStreamEvent(t, c.manager.finished, "stream release")
	}
}

func denyLifecycleStream(t *testing.T, c streamTestClients, method string, caller int) {
	t.Helper()
	cancel, result := startStream(t, c, method, caller, 30*time.Second)
	defer cancel()
	select {
	case err := <-result:
		require.Equal(t, codes.ResourceExhausted, status.Code(err), "an occupied allowance must reject the stream")
	case <-c.manager.started:
		t.Fatal("stream was admitted while its allowance was occupied")
	case <-time.After(5 * time.Second):
		t.Fatal("stream admission did not settle")
	}
}

func TestActiveStreamLimitsReleasePreservesOtherSelectorGroups(t *testing.T) {
	for _, method := range policyMethods {
		t.Run(method, func(t *testing.T) {
			c := newStreamTestClients(t, map[string]int{method: 1}, WorkloadAPIRateLimitConfig{}, nil)
			first := openLifecycleStream(t, c, method, 1)
			other := openLifecycleStream(t, c, method, 3)
			first()
			denyLifecycleStream(t, c, method, 3)
			replacement := openLifecycleStream(t, c, method, 2)
			denyLifecycleStream(t, c, method, 1)
			denyLifecycleStream(t, c, method, 3)
			replacement()
			other()
			openLifecycleStream(t, c, method, 3)()
		})
	}
}

func TestActiveStreamLimitsReleasePreservesOtherMethods(t *testing.T) {
	for _, releasedMethod := range policyMethods {
		for _, retainedMethod := range policyMethods {
			if releasedMethod == retainedMethod {
				continue
			}
			t.Run(releasedMethod+"_then_"+retainedMethod, func(t *testing.T) {
				c := newStreamTestClients(t, map[string]int{"PerWorkload": 2, "Global": 4}, WorkloadAPIRateLimitConfig{}, nil)
				first := openLifecycleStream(t, c, releasedMethod, 7)
				retained := openLifecycleStream(t, c, retainedMethod, 8)
				otherGroup := openLifecycleStream(t, c, releasedMethod, 3)
				first()
				replacement := openLifecycleStream(t, c, releasedMethod, 8)
				// There is global capacity, but this selector set still has two streams.
				denyLifecycleStream(t, c, retainedMethod, 7)
				require.NoError(t, replaceStreamPolicy(t, c, map[string]int{"Global": 3}))
				denyLifecycleStream(t, c, retainedMethod, 10)
				replacement()
				retained()
				otherGroup()
				openLifecycleStream(t, c, releasedMethod, 7)()
			})
		}
	}
}

func TestActiveStreamLimitsReleaseWhileDisabled(t *testing.T) {
	fields := append([]string{"Global", "PerWorkload"}, policyMethods...)
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			method := field
			if field == "Global" || field == "PerWorkload" {
				method = "FetchJWTBundles"
			}
			c := newStreamTestClients(t, map[string]int{field: 2}, WorkloadAPIRateLimitConfig{}, nil)
			first := openLifecycleStream(t, c, method, 1)
			require.NoError(t, replaceStreamPolicy(t, c, nil))
			retained := openLifecycleStream(t, c, method, 2)
			first()
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 2}))
			replacement := openLifecycleStream(t, c, method, 1)
			denyLifecycleStream(t, c, method, 2)
			retained()
			replacement()
			require.NoError(t, replaceStreamPolicy(t, c, map[string]int{field: 1}))
			openLifecycleStream(t, c, method, 2)()
		})
	}
}
