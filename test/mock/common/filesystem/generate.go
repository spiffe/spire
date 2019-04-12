package filesystem_mock

//go:generate $GOPATH/bin/mockgen -source ../../../../pkg/agent/common/cgroups/cgroups.go -destination filesystem.go -package filesystem_mock
