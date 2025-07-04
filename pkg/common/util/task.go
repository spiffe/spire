package util

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
)

type TaskRunner struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelCauseFunc
}

func NewTaskRunner(ctx context.Context, cancel context.CancelCauseFunc) *TaskRunner {
	return &TaskRunner{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (t *TaskRunner) StartTasks(tasks ...func(context.Context) error) {
	runTask := func(task func(context.Context) error) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v\n%s\n", r, string(debug.Stack()))
			}
			t.wg.Done()
		}()
		return task(t.ctx)
	}

	t.wg.Add(len(tasks))
	for _, task := range tasks {
		go func() {
			err := runTask(task)
			if err != nil {
				t.cancel(err)
			}
		}()
	}
}

func (t *TaskRunner) Wait() error {
	t.wg.Wait()
	return context.Cause(t.ctx)
}

// RunTasks executes all the provided functions concurrently and waits for
// them all to complete. If a function returns an error, all other functions
// are canceled (i.e. the context they are passed is canceled) and the error is
// returned. If all functions finish to completion successfully, RunTasks
// returns nil. If the context passed to RunTasks is canceled then each
// function is canceled and RunTasks returns ctx.Err(). Tasks passed to
// RunTasks MUST support cancellation via the provided context for RunTasks to
// work properly.
func RunTasks(ctx context.Context, tasks ...func(context.Context) error) error {
	nctx, cancel := context.WithCancelCause(ctx)
	t := NewTaskRunner(nctx, cancel)
	t.StartTasks(tasks...)
	return t.Wait()
}
