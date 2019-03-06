package main

import "context"

func CreateNamespace(ctx context.Context, name string) error {
	return kubectlRun("create", "namespace", name)
}

func DeleteNamespaceIfExist(ctx context.Context, name string) error {
	return kubectlRun("delete", "--ignore-not-found", "namespace", name)
}
