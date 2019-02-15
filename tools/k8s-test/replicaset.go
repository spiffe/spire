package main

import (
	"context"
	"fmt"

	v1beta1 "k8s.io/api/extensions/v1beta1"
)

func GetReplicaSet(ctx context.Context, name string) (*v1beta1.ReplicaSet, error) {
	obj := new(v1beta1.ReplicaSet)
	ok, err := getObject(ctx, "rs", name, obj, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no such replica set %q", name)
	}
	return obj, nil
}

func GetReplicaSetByOwner(ctx context.Context, name string, owner Object) (*v1beta1.ReplicaSet, error) {
	obj := new(v1beta1.ReplicaSet)
	ok, err := getObject(ctx, "rs", name, obj, &owner)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no replica set %q owned by %s", owner, owner)
	}
	return obj, nil
}

func GetReplicaSets(ctx context.Context) ([]v1beta1.ReplicaSet, error) {
	list := new(v1beta1.ReplicaSetList)
	if err := getList(ctx, "rs", list, nil); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, NotFound.New("no replica sets")
	}
	return list.Items, nil
}

func GetReplicaSetsByOwner(ctx context.Context, owner Object) ([]v1beta1.ReplicaSet, error) {
	list := new(v1beta1.ReplicaSetList)
	if err := getList(ctx, "rs", list, &owner); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, NotFound.New("no replica sets owned by %s", owner)
	}
	return list.Items, nil
}

func CheckReplicaSetReady(rs *v1beta1.ReplicaSet) error {
	if rs.Status.AvailableReplicas < rs.Status.Replicas {
		return fmt.Errorf("only %d of %d replicas available", rs.Status.AvailableReplicas, rs.Status.Replicas)
	}
	return nil
}
