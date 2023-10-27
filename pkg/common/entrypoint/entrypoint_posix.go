//go:build !windows

package entrypoint

import (
	"context"
	"os"
)

type EntryPoint struct {
	runCmdFn func(ctx context.Context, args []string) int
}

func NewEntryPoint(runFn func(ctx context.Context, args []string) int) *EntryPoint {
	return &EntryPoint{
		runCmdFn: runFn,
	}
}

func (e *EntryPoint) Main() int {
	return e.runCmdFn(context.Background(), os.Args[1:])
}
