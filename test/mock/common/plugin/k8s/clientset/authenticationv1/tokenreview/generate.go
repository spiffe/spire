package mock_tokenreview

//go:generate $GOPATH/bin/mockgen -destination=tokenreview.go -package=mock_tokenreview k8s.io/client-go/kubernetes/typed/authentication/v1 TokenReviewInterface
