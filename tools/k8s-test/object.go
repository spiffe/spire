package main

import (
	"errors"
	"fmt"
	"strings"
)

const (
	ClusterRoleKind        = "ClusterRole"
	ClusterRoleBindingKind = "ClusterRoleBinding"
	ConfigMapKind          = "ConfigMap"
	DaemonSetKind          = "DaemonSet"
	DeploymentKind         = "Deployment"
	NamespaceKind          = "Namespace"
	PodKind                = "Pod"
	ReplicaSetKind         = "ReplicaSet"
	RoleBindingKind        = "RoleBinding"
	RoleKind               = "Role"
	SecretKind             = "Secret"
	ServiceAccountKind     = "ServiceAccount"
	ServiceKind            = "Service"
	StatefulSetKind        = "StatefulSet"
)

type Object struct {
	Kind string
	Name string
}

func (o *Object) String() string {
	return fmt.Sprintf("%s/%s", strings.ToLower(o.Kind), o.Name)
}

func DaemonSetObject(name string) Object {
	return Object{Kind: DaemonSetKind, Name: name}
}

func DeploymentObject(name string) Object {
	return Object{Kind: DeploymentKind, Name: name}
}

func ReplicaSetObject(name string) Object {
	return Object{Kind: ReplicaSetKind, Name: name}
}

func PodObject(name string) Object {
	return Object{Kind: PodKind, Name: name}
}

func StatefulSetObject(name string) Object {
	return Object{Kind: StatefulSetKind, Name: name}
}

func ParseObject(s string) (Object, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return Object{}, errors.New("expected kind/name for object identifer")
	}
	kind := strings.ToLower(parts[0])
	switch kind {
	case "ds", "daemonset":
		return DaemonSetObject(parts[1]), nil
	case "deployment":
		return DeploymentObject(parts[1]), nil
	case "statefulset":
		return StatefulSetObject(parts[1]), nil
	case "rs", "replicaset":
		return ReplicaSetObject(parts[1]), nil
	case "pod":
		return PodObject(parts[1]), nil
	default:
		return Object{}, fmt.Errorf("unknown object kind %q", parts[0])
	}
}
