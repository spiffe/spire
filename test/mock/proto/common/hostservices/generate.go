package mock_hostservices

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/common/hostservices MetricsService > metricsservice_mock.go"
