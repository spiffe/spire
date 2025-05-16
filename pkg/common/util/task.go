package util

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
)

type TaskRunner struct {
	wg        sync.WaitGroup
	ctx       context.Context
	cancels   []context.CancelFunc
	errch     chan error
	taskCount int
}

func NewTaskRunner(ctx context.Context) *TaskRunner {
	return &TaskRunner{
		ctx:   ctx,
		errch: make(chan error, 1),
	}
}

func (t *TaskRunner) StartTasks(tasks ...func(context.Context) error) {
	ctx, cancel := context.WithCancel(t.ctx)
	t.cancels = append(t.cancels, cancel)

	runTask := func(task func(context.Context) error) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v\n%s\n", r, string(debug.Stack()))
			}
			t.wg.Done()
		}()
		return task(ctx)
	}

	lenTasks := len(tasks)
	t.taskCount += lenTasks
	t.wg.Add(lenTasks)
	for _, task := range tasks {
		go func() {
			t.errch <- runTask(task)
		}()
	}
}

func (t *TaskRunner) Wait() error {
	defer func() {
		for _, cancel := range t.cancels {
			cancel()
		}
		t.wg.Wait()
	}()

	for complete := 0; complete < t.taskCount; {
		select {
		case <-t.ctx.Done():
			return t.ctx.Err()
		case err := <-t.errch:
			if err != nil {
				return err
			}
			complete++
		}
	}

	return nil
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
	t := NewTaskRunner(ctx)
	t.StartTasks(tasks...)
	return t.Wait()
}
