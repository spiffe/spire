package mock_corev1

//go:generate $GOPATH/bin/mockgen -destination=corev1.go -package=mock_corev1 k8s.io/client-go/kubernetes/typed/core/v1 CoreV1Interface
