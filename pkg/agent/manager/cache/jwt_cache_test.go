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

func TestJWTSVIDCache(t *testing.T) {
	now := time.Now()
	tok1 := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRaRGZZaXcxdUd6TXdkTVlITDdGRVl5SzhIT0tLd0xYIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3MjQzNjU3MzEsImlhdCI6MTcyNDI3OTQwNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.dFr-oWhm5tK0bBuVXt-sGESM5l7hhoY-Gtt5DkuFoJL5Y9d4ZfmicCvUCjL4CqDB3BO_cPqmFfrO7H7pxQbGLg"
	tok2 := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNKMXI5TVY4OTZTWXBMY0RMUjN3Q29QRHprTXpkN25tIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3Mjg1NzEwMjUsImlhdCI6MTcyODU3MDcyNSwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.1YnDj7nknwIHEuNKEN0cNypXKS4SUeILXlNOsOs2XElHzfKhhDcl0sYKYtQc1Itf6cygz9C16VOQ_Yjoos2Qfg"
	jwtSVID1 := &client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	jwtSVID2 := &client.JWTSVID{Token: tok2, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}

	fakeMetrics := fakemetrics.New()
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	cache := NewJWTSVIDCache(log, fakeMetrics, 8)

	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")

	// JWT is not cached
	actual, ok := cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.False(t, ok)
	assert.Nil(t, actual)

	// JWT is cached
	cache.SetJWTSVID(spiffeID, []string{"bar"}, jwtSVID1)
	actual, ok = cache.GetJWTSVID(spiffeID, []string{"bar"})
	assert.True(t, ok)
	assert.Equal(t, jwtSVID1, actual)

	// Test tainting of JWt-SVIDs
	ctx := context.Background()
	keyID1 := "dZDfYiw1uGzMwdMYHL7FEYyK8HOKKwLX"
	keyID2 := "cJ1r9MV896SYpLcDLR3wCoPDzkMzd7nm"
	for _, tt := range []struct {
		name              string
		taintedKeyIDs     map[string]struct{}
		setJWTSVIDsCached func(cache *JWTSVIDCache)
		expectLogs        []spiretest.LogEntry
		expectMetrics     []fakemetrics.MetricItem
	}{
		{
			name:          "one authority tainted, one JWT-SVID",
			taintedKeyIDs: map[string]struct{}{keyID1: {}},
			setJWTSVIDsCached: func(cache *JWTSVIDCache) {
				cache.SetJWTSVID(spiffeID, []string{"audience-1"}, jwtSVID1)
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority",
					Data: logrus.Fields{
						telemetry.TaintedJWTSVIDs:    "1",
						telemetry.JWTAuthorityKeyIDs: keyID1,
					},
				},
			},
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type: fakemetrics.AddSampleType,
					Key:  []string{telemetry.CacheManager, telemetry.TaintedJWTSVIDs, agent.CacheTypeWorkload},
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
			},
		},
		{
			name:          "one authority tainted, multiple JWT-SVIDs",
			taintedKeyIDs: map[string]struct{}{keyID1: {}},
			setJWTSVIDsCached: func(cache *JWTSVIDCache) {
				cache.SetJWTSVID(spiffeID, []string{"audience-1"}, jwtSVID1)
				cache.SetJWTSVID(spiffeID, []string{"audience-2"}, jwtSVID1)
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority",
					Data: logrus.Fields{
						telemetry.TaintedJWTSVIDs:    "2",
						telemetry.JWTAuthorityKeyIDs: keyID1,
					},
				},
			},
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type: fakemetrics.AddSampleType,
					Key:  []string{telemetry.CacheManager, telemetry.TaintedJWTSVIDs, agent.CacheTypeWorkload},
					Val:  2,
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
			},
		},
		{
			name:          "multiple authorities tainted, multiple JWT-SVIDs",
			taintedKeyIDs: map[string]struct{}{keyID1: {}, keyID2: {}},
			setJWTSVIDsCached: func(cache *JWTSVIDCache) {
				cache.SetJWTSVID(spiffeID, []string{"audience-1"}, jwtSVID1)
				cache.SetJWTSVID(spiffeID, []string{"audience-2"}, jwtSVID1)
				cache.SetJWTSVID(spiffeID, []string{"audience-3"}, jwtSVID2)
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority",
					Data: logrus.Fields{
						telemetry.TaintedJWTSVIDs:    "2",
						telemetry.JWTAuthorityKeyIDs: keyID1,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority",
					Data: logrus.Fields{
						telemetry.TaintedJWTSVIDs:    "1",
						telemetry.JWTAuthorityKeyIDs: keyID2,
					},
				},
			},
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type: fakemetrics.AddSampleType,
					Key:  []string{telemetry.CacheManager, telemetry.TaintedJWTSVIDs, agent.CacheTypeWorkload},
					Val:  3,
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
			},
		},
		{
			name:          "none of the authorities tainted is in cache",
			taintedKeyIDs: map[string]struct{}{"not-cached-1": {}, "not-cached-2": {}},
			setJWTSVIDsCached: func(cache *JWTSVIDCache) {
				cache.SetJWTSVID(spiffeID, []string{"audience-1"}, jwtSVID1)
				cache.SetJWTSVID(spiffeID, []string{"audience-2"}, jwtSVID1)
				cache.SetJWTSVID(spiffeID, []string{"audience-3"}, jwtSVID2)
			},
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type: fakemetrics.AddSampleType,
					Key:  []string{telemetry.CacheManager, telemetry.TaintedJWTSVIDs, agent.CacheTypeWorkload},
					Val:  0,
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
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewJWTSVIDCache(log, fakeMetrics, 8)
			if tt.setJWTSVIDsCached != nil {
				tt.setJWTSVIDsCached(cache)
			}

			// Remove tainted authority, should not be cached anymore
			cache.TaintJWTSVIDs(ctx, tt.taintedKeyIDs)
			actual, ok = cache.GetJWTSVID(spiffeID, []string{"bar"})
			assert.False(t, ok)
			assert.Nil(t, actual)

			spiretest.AssertLogsAnyOrder(t, logHook.AllEntries(), tt.expectLogs)
			assert.Equal(t, tt.expectMetrics, fakeMetrics.AllMetrics())
			resetLogsAndMetrics(logHook, fakeMetrics)
		})
	}
}

func TestJWTSVIDCacheSize(t *testing.T) {
	fakeMetrics := fakemetrics.New()
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	cache := NewJWTSVIDCache(log, fakeMetrics, 2)

	now := time.Now()
	jwtSvid1 := &client.JWTSVID{Token: "1", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	jwtSvid2 := &client.JWTSVID{Token: "2", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	jwtSvid3 := &client.JWTSVID{Token: "3", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}

	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")
	cache.SetJWTSVID(spiffeID, []string{"audience-1"}, jwtSvid1)
	cache.SetJWTSVID(spiffeID, []string{"audience-2"}, jwtSvid2)
	cache.SetJWTSVID(spiffeID, []string{"audience-3"}, jwtSvid3)

	// The first SVID that was inserted into the cache should have been evicted.
	_, ok := cache.GetJWTSVID(spiffeID, []string{"audience-1"})
	assert.False(t, ok)

	actual, ok := cache.GetJWTSVID(spiffeID, []string{"audience-2"})
	assert.True(t, ok)
	assert.Equal(t, jwtSvid2, actual)

	actual, ok = cache.GetJWTSVID(spiffeID, []string{"audience-3"})
	assert.True(t, ok)
	assert.Equal(t, jwtSvid3, actual)

	// Make the second token the most recently used token
	_, _ = cache.GetJWTSVID(spiffeID, []string{"audience-2"})

	// Insert a token
	cache.SetJWTSVID(spiffeID, []string{"audience-1"}, jwtSvid1)

	actual, ok = cache.GetJWTSVID(spiffeID, []string{"audience-2"})
	assert.True(t, ok)
	assert.Equal(t, jwtSvid2, actual)

	_, ok = cache.GetJWTSVID(spiffeID, []string{"audience-3"})
	assert.False(t, ok)
}

func TestJWTSVIDCacheKeyHashing(t *testing.T) {
	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")
	now := time.Now()
	expected := &client.JWTSVID{Token: "X", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}

	fakeMetrics := fakemetrics.New()
	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	cache := NewJWTSVIDCache(log, fakeMetrics, 8)
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
