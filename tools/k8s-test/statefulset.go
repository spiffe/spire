package main

import (
	"context"
	"errors"

	"k8s.io/api/apps/v1beta1"
)

func GetStatefulSet(ctx context.Context, name string) (*v1beta1.StatefulSet, error) {
	obj := new(v1beta1.StatefulSet)
	ok, err := getObject(ctx, "statefulset", name, obj, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no such stateful set %q", name)
	}
	return obj, nil
}

func CheckStatefulSetReady(d *v1beta1.StatefulSet) error {
	if d.Status.ReadyReplicas < d.Status.Replicas {
		return errors.New("not all replicas are ready")
	}
	return nil
}
