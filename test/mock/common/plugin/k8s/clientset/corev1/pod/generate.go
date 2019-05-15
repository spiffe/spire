package mock_pod

//go:generate $GOPATH/bin/mockgen -destination=pod.go -package=mock_pod k8s.io/client-go/kubernetes/typed/core/v1 PodInterface
