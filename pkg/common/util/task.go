package util

import (
	"context"
	"fmt"
	"sync"
)

// RunTasks executes all of the provided functions concurrently and waits for
// them all to complete. If a function returns an error, all other functions
// are canceled (i.e. the context they are passed is canceled) and the error is
// returned. If all functions finish to completion successfully, RunTasks
// returns nil. If the context passed to RunTasks is canceled then each
// function is canceled and RunTasks returns ctx.Err(). Tasks passed to
// RunTasks MUST support cancelation via the provided context for RunTasks to
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
				if e, ok := r.(error); ok {
					errch <- e
				} else {
					errch <- fmt.Errorf("panic: %v", r)
				}
			} else {
				errch <- err
			}
			wg.Done()
		}()
		return task(ctx)
	}

	wg.Add(len(tasks))
	for _, task := range tasks {
		go runTask(task)
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
