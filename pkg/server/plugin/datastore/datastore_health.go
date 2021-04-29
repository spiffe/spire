package datastore

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/common/health"
)

type Health struct {
	DataStore DataStore
}

func (h *Health) CheckHealth() health.State {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := h.DataStore.ListBundles(ctx, &ListBundlesRequest{})

	// Both liveness and readiness are determined by the datastore's
	// ability to list all the bundles.
	ready := err == nil
	live := err == nil

	return health.State{
		Live:  live,
		Ready: ready,
		ReadyDetails: HealthDetails{
			ListBundleErr: errString(err),
		},
		LiveDetails: HealthDetails{
			ListBundleErr: errString(err),
		},
	}
}

type HealthDetails struct {
	ListBundleErr string `json:"list_bundle_err,omitempty"`
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
