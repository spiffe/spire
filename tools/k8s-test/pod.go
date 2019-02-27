package main

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
)

func GetPods(ctx context.Context) ([]v1.Pod, error) {
	var list v1.PodList
	if err := getList(ctx, "pods", &list, nil); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, NotFound.New("no pods")
	}
	return list.Items, nil
}

func GetPod(ctx context.Context, name string) (*v1.Pod, error) {
	obj := new(v1.Pod)
	ok, err := getObject(ctx, "pods", name, obj, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no such pod %q", name)
	}
	return obj, nil
}

func GetPodsByOwner(ctx context.Context, owner Object) ([]v1.Pod, error) {
	var list v1.PodList
	if err := getList(ctx, "pods", &list, &owner); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, NotFound.New("no pods owned by %s", owner)
	}
	return list.Items, nil
}

func GetPodByOwner(ctx context.Context, name string, owner Object) (*v1.Pod, error) {
	obj := new(v1.Pod)
	ok, err := getObject(ctx, "pods", name, obj, &owner)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no pod %q owned by %s", name, owner)
	}
	return obj, nil
}

func CheckPodReady(pod *v1.Pod) error {
	for _, status := range pod.Status.ContainerStatuses {
		if w := status.State.Waiting; w != nil {
			return fmt.Errorf("container %q is not running (%s)", status.Name, w.Reason)
		}
		if t := status.State.Terminated; t != nil {
			return fmt.Errorf("container %q is has terminated (%s)", status.Name, t.Reason)
		}
	}
	return nil
}
