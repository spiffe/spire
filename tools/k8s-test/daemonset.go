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

func GetDaemonSets(ctx context.Context) ([]v1beta1.DaemonSet, error) {
	var list v1beta1.DaemonSetList
	if err := getList(ctx, "ds", &list, nil); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, NotFound.New("no daemon sets")
	}
	return list.Items, nil
}

func CheckDaemonSetReady(ds *v1beta1.DaemonSet) error {
	return nil
}
