package mock_apiserver

//go:generate $GOPATH/bin/mockgen -source ../../../../../../pkg/common/plugin/k8s/apiserver/client.go -destination client.go -package mock_apiserver
