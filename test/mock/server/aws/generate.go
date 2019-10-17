package mock_aws

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/pkg/server/plugin/nodeattestor/aws EC2Client > ec2client_mock.go"
