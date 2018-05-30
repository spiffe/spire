package mock_registration

//go:generate sh -c "mockgen github.com/spiffe/spire/proto/api/registration RegistrationClient,RegistrationServer > registration.go"
