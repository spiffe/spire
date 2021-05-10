package catalog

import (
	"io"

	"github.com/zeebo/errs"
)

type closerGroup []io.Closer

func (cs closerGroup) Close() error {
	// Close in reverse order.
	var errs errs.Group
	for i := len(cs) - 1; i >= 0; i-- {
		errs.Add(cs[i].Close())
	}
	return errs.Err()
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
