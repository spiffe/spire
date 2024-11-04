package util

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
)

// RunTasks executes all the provided functions concurrently and waits for
// them all to complete. If a function returns an error, all other functions
// are canceled (i.e. the context they are passed is canceled) and the error is
// returned. If all functions finish to completion successfully, RunTasks
// returns nil. If the context passed to RunTasks is canceled then each
// function is canceled and RunTasks returns ctx.Err(). Tasks passed to
// RunTasks MUST support cancellation via the provided context for RunTasks to
// work properly.
func RunTasks(ctx context.Context, tasks ...func(context.Context) error) error {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	errch := make(chan error, len(tasks))

	runTask := func(task func(context.Context) error) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v\n%s\n", r, string(debug.Stack()))
			}
			wg.Done()
		}()
		return task(ctx)
	}

	wg.Add(len(tasks))
	for _, task := range tasks {
		task := task
		go func() {
			errch <- runTask(task)
		}()
	}

	for complete := 0; complete < len(tasks); {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errch:
			if err != nil {
				return err
			}
			complete++
		}
	}

	return nil
}

// SerialRun executes all the provided functions serially.
// If all functions finish to completion successfully, SerialRun
// returns nil. If the context passed to SerialRun is canceled
// then each function is canceled and SerialRun returns ctx.Err().
// Tasks passed to SerialRun MUST support cancellation via the provided
// context for SerialRun to work properly.
func SerialRun(tasks ...func(context.Context) error) func(ctx context.Context) error {
	return func(ctx context.Context) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v\n%s\n", r, string(debug.Stack()))
			}
		}()

		for _, task := range tasks {
			if err := task(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}
