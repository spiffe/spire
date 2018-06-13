package mock_workloadattestor

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/agent/workloadattestor WorkloadAttestor,WorkloadAttestorPlugin > workloadattestor_mock.go"
