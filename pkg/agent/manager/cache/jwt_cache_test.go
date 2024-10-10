package cache

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
)

func TestJWTSVIDCacheBasic(t *testing.T) {
	now := time.Now()
	tok := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRaRGZZaXcxdUd6TXdkTVlITDdGRVl5SzhIT0tLd0xYIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3MjQzNjU3MzEsImlhdCI6MTcyNDI3OTQwNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.dFr-oWhm5tK0bBuVXt-sGESM5l7hhoY-Gtt5DkuFoJL5Y9d4ZfmicCvUCjL4CqDB3BO_cPqmFfrO7H7pxQbGLg"
	keyID := "dZDfYiw1uGzMwdMYHL7FEYyK8HOKKwLX"
	expected := &client.JWTSVID{Token: tok, IssuedAt: now, ExpiresAt: now.Add(time.Second)}

	fakeMetrics := fakemetrics.New()
	log, hook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	cache := NewJWTSVIDCache(log, fakeMetrics)

	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")

	// JWT is not cached
	actual, ok := cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.False(t, ok)
	assert.Nil(t, actual)

	// JWT is cached
	cache.SetJWTSVID(spiffeID, []string{"bar"}, expected)
	actual, ok = cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.True(t, ok)
	assert.Equal(t, expected, actual)

	// Remove tainted authority, should not be cached anymore
	cache.TaintJWTSVIDs(context.Background(), map[string]struct{}{keyID: {}})
	actual, ok = cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.False(t, ok)
	assert.Nil(t, actual)

	// Assert logs and metrics
	expectLogs := []spiretest.LogEntry{
		{
			Level:   logrus.InfoLevel,
			Message: "JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority",
			Data: logrus.Fields{
				telemetry.CountJWTSVIDs:      "1",
				telemetry.JWTAuthorityKeyIDs: keyID,
			},
		},
	}
	expectMetrics := []fakemetrics.MetricItem{
		{
			Type: fakemetrics.AddSampleType,
			Key:  []string{telemetry.CacheManager, telemetry.CountJWTSVIDs, agent.CacheTypeWorkload},
			Val:  1,
		},
		{
			Type:   fakemetrics.IncrCounterWithLabelsType,
			Key:    []string{telemetry.CacheManager, agent.CacheTypeWorkload, telemetry.ProcessTaintedJWTSVIDs},
			Val:    1,
			Labels: []metrics.Label{{Name: "status", Value: "OK"}},
		},
		{
			Type:   fakemetrics.MeasureSinceWithLabelsType,
			Key:    []string{telemetry.CacheManager, agent.CacheTypeWorkload, telemetry.ProcessTaintedJWTSVIDs, telemetry.ElapsedTime},
			Val:    0,
			Labels: []metrics.Label{{Name: "status", Value: "OK"}},
		},
	}

	spiretest.AssertLogs(t, hook.AllEntries(), expectLogs)
	assert.Equal(t, expectMetrics, fakeMetrics.AllMetrics())
}

func TestJWTSVIDCacheKeyHashing(t *testing.T) {
	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")
	now := time.Now()
	expected := &client.JWTSVID{Token: "X", IssuedAt: now, ExpiresAt: now.Add(time.Second)}

	fakeMetrics := fakemetrics.New()
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	cache := NewJWTSVIDCache(log, fakeMetrics)
	cache.SetJWTSVID(spiffeID, []string{"ab", "cd"}, expected)

	// JWT is cached
	actual, ok := cache.GetJWTSVID(spiffeID, []string{"ab", "cd"})
	assert.True(t, ok)
	assert.Equal(t, expected, actual)

	// JWT is not cached, despite concatenation of audiences (in lexicographical order) matching
	// that of the cached item
	actual, ok = cache.GetJWTSVID(spiffeID, []string{"a", "bcd"})
	assert.False(t, ok)
	assert.Nil(t, actual)
}
