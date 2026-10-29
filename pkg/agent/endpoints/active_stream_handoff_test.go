package endpoints

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Probe a policy update concurrent with a newly queued call, through the public endpoint API.
func TestActiveStreamLimitsImmediatePolicyHandoff(t *testing.T) {
	old := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(old)
	c := queueClients(t, map[string]int{"Global": 1, "MaxPending": 1}, WorkloadAPIRateLimitConfig{})
	statsMethod := reflect.ValueOf(c.endpoint).MethodByName("WorkloadAPIStreamStats")
	updateMethod := reflect.ValueOf(c.endpoint).MethodByName("UpdateWorkloadAPIStreamLimits")
	require.True(t, statsMethod.IsValid() && updateMethod.IsValid(), "endpoints must expose live policy replacement and stats")
	pendingCount := func() int { return int(statsMethod.Call(nil)[0].FieldByName("Pending").Int()) }
	policies := make([]reflect.Value, 3)
	for _, limit := range []int{1, 2} {
		policy := reflect.New(updateMethod.Type().In(0)).Elem()
		policy.FieldByName("Global").SetInt(int64(limit))
		policy.FieldByName("MaxPending").SetInt(1)
		policies[limit] = policy
	}
	updatePolicy := func(limit int) error {
		result := updateMethod.Call([]reflect.Value{policies[limit]})[0]
		if result.IsNil() {
			return nil
		}
		return result.Interface().(error)
	}
	holder := queueStart(t, c, "FetchX509Bundles", 1, 120*time.Second)
	queueAdmitted(t, c, holder)
	for i := range 2000 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		updated := make(chan error, 1)
		go func() {
			for pendingCount() == 0 {
				if ctx.Err() != nil {
					updated <- ctx.Err()
					return
				}
				runtime.Gosched()
			}
			updated <- updatePolicy(2)
		}()
		waiter := queueStart(t, c, "FetchX509Bundles", 3, 30*time.Second)
		err := <-updated
		cancel()
		require.NoError(t, err, "iteration %d", i)
		queueAdmitted(t, c, waiter)
		queueStop(t, c, waiter, true)
		waitQueueStats(t, c, 1, 0)
		require.NoError(t, updatePolicy(1))
	}
	queueStop(t, c, holder, true)
	waitQueueStats(t, c, 0, 0)
}
