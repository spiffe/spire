package main

import (
	"context"
	"time"
)

func WaitForObjects(ctx context.Context, objects []Object) error {
	for _, object := range objects {
		switch object.Kind {
		case "Deployment":
			if err := WaitForDeployment(ctx, object.Name); err != nil {
				return err
			}
		case "DaemonSet":
			if err := WaitForDaemonSet(ctx, object.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func WaitForDeployment(ctx context.Context, name string) error {
	replicaSets, err := GetReplicaSetsByOwner(ctx, Object{Kind: "Deployment", Name: name})
	if err != nil {
		return err
	}

	for _, replicaSet := range replicaSets {
		if err := WaitForReplicaSet(ctx, replicaSet.Name); err != nil {
			return err
		}
	}

	return waitFor(ctx, func(ctx context.Context) (bool, error) {
		deployment, err := GetDeployment(ctx, name)
		if err != nil {
			return false, err
		}
		if err := CheckDeploymentReady(deployment); err != nil {
			Warnln("deployment %q is not ready yet: %v", name, err.Error())
			return false, nil
		}
		Goodln("deployment %q is ready", name)
		return true, nil
	})
}

func WaitForReplicaSet(ctx context.Context, name string) error {
	pods, err := GetPodsByOwner(ctx, Object{Kind: "ReplicaSet", Name: name})
	if err != nil {
		return err
	}

	for _, pod := range pods {
		if err := WaitForPod(ctx, pod.Name); err != nil {
			return err
		}
	}

	return waitFor(ctx, func(ctx context.Context) (bool, error) {
		replicaSet, err := GetReplicaSet(ctx, name)
		if err != nil {
			return false, err
		}
		if err := CheckReplicaSetReady(replicaSet); err != nil {
			Warnln("replica set %q is not ready yet: %v", name, err.Error())
			return false, nil
		}
		Goodln("replica set %q is ready", name)
		return true, nil
	})
}

func WaitForDaemonSet(ctx context.Context, name string) error {
	pods, err := GetPodsByOwner(ctx, Object{Kind: "DaemonSet", Name: name})
	if err != nil {
		return err
	}

	for _, pod := range pods {
		if err := WaitForPod(ctx, pod.Name); err != nil {
			return err
		}
	}

	return waitFor(ctx, func(ctx context.Context) (bool, error) {
		ds, err := GetDaemonSet(ctx, name)
		if err != nil {
			return false, err
		}
		if err := CheckDaemonSetReady(ds); err != nil {
			Warnln("daemon set %q is not ready yet: %v", name, err.Error())
			return false, nil
		}
		Goodln("daemon set %q is ready", name)
		return true, nil
	})
}

func WaitForPod(ctx context.Context, name string) error {
	return waitFor(ctx, func(ctx context.Context) (bool, error) {
		pod, err := GetPod(ctx, name)
		if err != nil {
			return false, err
		}
		if err := CheckPodReady(pod); err != nil {
			Warnln("pod %q is not ready yet: %v", name, err.Error())
			return false, nil
		}
		Goodln("pod %q is ready", name)
		return true, nil
	})
}

func waitFor(ctx context.Context, fn func(context.Context) (bool, error)) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		ok, err := fn(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
