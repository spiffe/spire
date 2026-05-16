package catalog

import (
	"errors"
	"io"
	"slices"
	"time"

	"google.golang.org/grpc"
)

type closerGroup []io.Closer

func (cs closerGroup) Close() error {
	// Close in reverse order.
	var errs error
	for _, c := range slices.Backward(cs) {
		errs = errors.Join(errs, c.Close())
	}

	return errs
}

type closerFunc func()

func closerFuncs(fns ...func()) closerGroup {
	var closers closerGroup
	for _, fn := range fns {
		closers = append(closers, closerFunc(fn))
	}
	return closers
}

func (fn closerFunc) Close() error {
	fn()
	return nil
}

func gracefulStopWithTimeout(s *grpc.Server) bool {
	done := make(chan struct{})

	go func() {
		s.GracefulStop()
		close(done)
	}()

	t := time.NewTimer(time.Minute)
	defer t.Stop()

	select {
	case <-done:
		return true
	case <-t.C:
		s.Stop()
		return false
	}
}
