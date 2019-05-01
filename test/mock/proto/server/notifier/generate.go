package mock_notifier

//go:generate sh -c "$GOPATH/bin/mockgen github.com/spiffe/spire/proto/spire/server/notifier Notifier,Plugin > notifier.go"
