package mock_workloadattestor

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/agent/workloadattestor WorkloadAttestor,Plugin > workloadattestor_mock.go"
