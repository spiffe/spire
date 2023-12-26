package endpoints

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthorizedEntryFetcherWithEventsBasedCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
	assert.NoError(t, err)
	assert.NotNil(t, ef)
}

func TestNewAuthorizedEntryFetcherWithEventsBasedCacheErrorBuildingCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	buildErr := errors.New("build error")
	ds.SetNextError(buildErr)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
	assert.Error(t, err)
	assert.Nil(t, ef)
}
