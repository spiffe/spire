package main

import (
	"context"

	v1beta1 "k8s.io/api/extensions/v1beta1"
)

func GetDaemonSet(ctx context.Context, name string) (*v1beta1.DaemonSet, error) {
	obj := new(v1beta1.DaemonSet)
	ok, err := getObject(ctx, "ds", name, obj, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no such daemon set %q", name)
	}
	return obj, nil
}

func CheckDaemonSetReady(ds *v1beta1.DaemonSet) error {
	// Intentionally left blank for the time being. If there is something beyond
	// DaemonSet pod readiness that we need to check that we can learn just
	// from the DaemonSet status, it can be put here.
	return nil
}
