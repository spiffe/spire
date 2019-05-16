package mock_authenticationv1

//go:generate $GOPATH/bin/mockgen -destination=authenticationv1.go -package=mock_authenticationv1 k8s.io/client-go/kubernetes/typed/authentication/v1 AuthenticationV1Interface
