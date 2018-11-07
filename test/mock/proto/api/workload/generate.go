package mock_workload

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/api/workload SpiffeWorkloadAPIClient,SpiffeWorkloadAPIServer,SpiffeWorkloadAPI_FetchX509SVIDClient,SpiffeWorkloadAPI_FetchX509SVIDServer,SpiffeWorkloadAPI_FetchJWTBundlesServer> workload.go"
