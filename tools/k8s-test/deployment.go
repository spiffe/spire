package main

import (
	"context"
	"errors"

	"k8s.io/api/apps/v1beta1"
)

func GetDeployment(ctx context.Context, name string) (*v1beta1.Deployment, error) {
	obj := new(v1beta1.Deployment)
	ok, err := getObject(ctx, "deployment", name, obj, nil)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NotFound.New("no such deployment %q", name)
	}
	return obj, nil
}

func GetDeployments(ctx context.Context) ([]v1beta1.Deployment, error) {
	list := new(v1beta1.DeploymentList)
	if err := getList(ctx, "deployments", list, nil); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, NotFound.New("no deployments")
	}
	return list.Items, nil
}

func CheckDeploymentReady(d *v1beta1.Deployment) error {
	if d.Status.UnavailableReplicas > 0 {
		return errors.New("there are unavailable replicas")
	}
	if d.Status.AvailableReplicas == 0 {
		return errors.New("there are no available replicas")
	}
	return nil
}
