package mock_node

//go:generate $GOPATH/bin/mockgen -destination=node.go -package=mock_node k8s.io/client-go/kubernetes/typed/core/v1 NodeInterface
