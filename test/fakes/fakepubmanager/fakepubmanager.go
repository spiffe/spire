package fakepubmanager

import (
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"golang.org/x/net/context"
)

func New() *fakePubManager {
	return &fakePubManager{
		bundleUpdatedCh: make(chan struct{}, 1),
	}
}

type fakePubManager struct {
	bundleUpdatedCh chan struct{}
}

func (m *fakePubManager) BundleUpdated() {
	m.bundleUpdatedCh <- struct{}{}
}

func (m *fakePubManager) WaitForUpdate(ctx context.Context) error {
	select {
	case <-m.bundleUpdatedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *fakePubManager) Init(bundlePublishers []bundlepublisher.BundlePublisher, dataStore datastore.DataStore) {

}

func (m *fakePubManager) Run(ctx context.Context) error {
	return nil
}
