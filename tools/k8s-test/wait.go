package main

import (
	"context"
	"time"

	"github.com/zeebo/errs"
)

func WaitForObjects(ctx context.Context, objects []Object, interval time.Duration) error {
	for _, object := range objects {
		switch object.Kind {
		case DeploymentKind:
			if err := WaitForDeployment(ctx, object.Name, interval); err != nil {
				return err
			}
		case DaemonSetKind:
			if err := WaitForDaemonSet(ctx, object.Name, interval); err != nil {
				return err
			}
		case StatefulSetKind:
			if err := WaitForStatefulSet(ctx, object.Name, interval); err != nil {
				return err
			}
		case ConfigMapKind:
		case NamespaceKind:
		case SecretKind:
		case ServiceKind:
		case ServiceAccountKind:
		default:
			// The default case is just to make sure we conciously handle all
			// objects that are configured, even if that means do nothing.
			return errs.New("cannot wait on %q object %q", object.Kind, object.Name)
		}
	}
	return nil
}

func WaitForDeployment(ctx context.Context, name string, interval time.Duration) error {
	replicaSets, err := GetReplicaSetsByOwner(ctx, DeploymentObject(name))
	if err != nil {
		return err
	}

	for _, replicaSet := range replicaSets {
		if err := WaitForReplicaSet(ctx, replicaSet.Name, interval); err != nil {
			return err
		}
	}

	return waitFor(ctx, interval, func(ctx context.Context) (bool, error) {
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

func WaitForStatefulSet(ctx context.Context, name string, interval time.Duration) error {
	pods, err := GetPodsByOwner(ctx, StatefulSetObject(name))
	if err != nil {
		return err
	}

	for _, pod := range pods {
		if err := WaitForPod(ctx, pod.Name, interval); err != nil {
			return err
		}
	}

	return waitFor(ctx, interval, func(ctx context.Context) (bool, error) {
		statefulSet, err := GetStatefulSet(ctx, name)
		if err != nil {
			return false, err
		}
		if err := CheckStatefulSetReady(statefulSet); err != nil {
			Warnln("stateful set %q is not ready yet: %v", name, err.Error())
			return false, nil
		}
		Goodln("stateful set %q is ready", name)
		return true, nil
	})
}

func WaitForReplicaSet(ctx context.Context, name string, interval time.Duration) error {
	pods, err := GetPodsByOwner(ctx, ReplicaSetObject(name))
	if err != nil {
		return err
	}

	for _, pod := range pods {
		if err := WaitForPod(ctx, pod.Name, interval); err != nil {
			return err
		}
	}

	return waitFor(ctx, interval, func(ctx context.Context) (bool, error) {
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

func WaitForDaemonSet(ctx context.Context, name string, interval time.Duration) error {
	pods, err := GetPodsByOwner(ctx, DaemonSetObject(name))
	if err != nil {
		return err
	}

	for _, pod := range pods {
		if err := WaitForPod(ctx, pod.Name, interval); err != nil {
			return err
		}
	}

	return waitFor(ctx, interval, func(ctx context.Context) (bool, error) {
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

func WaitForPod(ctx context.Context, name string, interval time.Duration) error {
	return waitFor(ctx, interval, func(ctx context.Context) (bool, error) {
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

func waitFor(ctx context.Context, interval time.Duration, fn func(context.Context) (bool, error)) error {
	ticker := time.NewTicker(interval)
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
