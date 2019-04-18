package mock_workload

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/api/workload SpiffeWorkloadAPIClient,SpiffeWorkloadAPIServer,SpiffeWorkloadAPI_FetchX509SVIDClient,SpiffeWorkloadAPI_FetchX509SVIDServer,SpiffeWorkloadAPI_FetchJWTBundlesServer> workload.go"
