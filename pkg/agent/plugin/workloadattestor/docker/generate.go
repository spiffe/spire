package docker

//go:generate $GOPATH/bin/mockgen -package docker -destination mock_dockerclient.go github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker Docker
