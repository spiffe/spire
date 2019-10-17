package mock_clientset

//go:generate $GOPATH/bin/mockgen -destination=clientset.go -package=mock_clientset k8s.io/client-go/kubernetes Interface
