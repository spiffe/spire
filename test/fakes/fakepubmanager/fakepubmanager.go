package fakepubmanager

import (
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"golang.org/x/net/context"
)

func New() *FakePubManager {
	return &FakePubManager{
		bundleUpdatedCh: make(chan struct{}, 1),
	}
}

type FakePubManager struct {
	bundleUpdatedCh chan struct{}
}

func (m *FakePubManager) BundleUpdated() {
	m.bundleUpdatedCh <- struct{}{}
}

func (m *FakePubManager) WaitForUpdate(ctx context.Context) error {
	select {
	case <-m.bundleUpdatedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *FakePubManager) Init(bundlePublishers []bundlepublisher.BundlePublisher, dataStore datastore.DataStore) {

}

func (m *FakePubManager) Run(ctx context.Context) error {
	return nil
}
