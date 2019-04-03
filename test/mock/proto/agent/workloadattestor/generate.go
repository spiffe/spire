package mock_workloadattestor

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/agent/workloadattestor WorkloadAttestor,WorkloadAttestorServer > workloadattestor_mock.go"
