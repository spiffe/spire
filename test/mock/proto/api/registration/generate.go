package mock_registration

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/api/registration RegistrationClient,RegistrationServer > registration.go"
