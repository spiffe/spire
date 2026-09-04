package entrypoint

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc"
)

type recordingReopener struct {
	called chan struct{}
}

// Reopen never blocks, so an extra call cannot hang the test.
func (r *recordingReopener) Reopen() error {
	select {
	case r.called <- struct{}{}:
	default:
	}
	return nil
}

// The reopen control code has to travel from the service control handler all
// the way to whatever holds the log file open, which is the only thing that
// makes it the Windows counterpart of SIGUSR2.
func TestExecuteForwardsReopenControlCode(t *testing.T) {
	logger, err := log.NewLogger()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reopener := &recordingReopener{called: make(chan struct{}, 1)}
	reopenReturned := make(chan struct{})
	go func() {
		defer close(reopenReturned)
		_ = log.ReopenOnSignal(logger, reopener)(ctx)
	}()

	changeRequest := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 2)
	s := &service{
		executeServiceFn: func(ctx context.Context, _ context.CancelFunc, _ []string) int {
			<-ctx.Done()
			return 0
		},
	}

	executeReturned := make(chan struct{})
	go func() {
		defer close(executeReturned)
		s.Execute([]string{"spire-agent", supportedCommand}, changeRequest, status)
	}()

	waitForServiceState(t, status, svc.Running)

	changeRequest <- svc.ChangeRequest{Cmd: reopenLogControlCode}
	select {
	case <-reopener.called:
	case <-time.After(time.Minute):
		t.Fatal("timed out waiting for the reopen request to reach the reopener")
	}

	// The reopen code must leave the service running, so stopping still has to
	// work afterwards.
	changeRequest <- svc.ChangeRequest{Cmd: svc.Stop}
	waitForServiceState(t, status, svc.StopPending)
	waitForClose(t, executeReturned, "Execute")

	cancel()
	waitForClose(t, reopenReturned, "the reopen loop")
}

func waitForClose(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatalf("timed out waiting for %s to return", what)
	}
}
