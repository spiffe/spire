package main

import (
	"errors"
	"fmt"
	"strings"
)

type Object struct {
	Kind string
	Name string
}

func (o *Object) String() string {
	return fmt.Sprintf("%s/%s", strings.ToLower(o.Kind), o.Name)
}

func ParseObject(s string) (Object, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return Object{}, errors.New("expected kind/name for object identifer")
	}
	kind := strings.ToLower(parts[0])
	switch kind {
	case "ds", "daemonset":
		return Object{Kind: "DaemonSet", Name: parts[1]}, nil
	case "deployment":
		return Object{Kind: "Deployment", Name: parts[1]}, nil
	case "rs", "replicaset":
		return Object{Kind: "ReplicaSet", Name: parts[1]}, nil
	case "pod":
		return Object{Kind: "Pod", Name: parts[1]}, nil
	default:
		return Object{}, fmt.Errorf("unknown object kind %q", parts[0])
	}
}
