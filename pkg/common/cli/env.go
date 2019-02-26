package cli

import (
	"fmt"
	"io"
	"os"
)

var (
	// this is the default environment used by commands
	DefaultEnv = &Env{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
)

// Env provides an pluggable environment for CLI commands that facilitates easy
// testing.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (e *Env) Printf(format string, args ...interface{}) error {
	_, err := fmt.Fprintf(e.Stdout, format, args...)
	return err
}

func (e *Env) Println(args ...interface{}) error {
	_, err := fmt.Fprintln(e.Stdout, args...)
	return err
}

func (e *Env) ErrPrintf(format string, args ...interface{}) error {
	_, err := fmt.Fprintf(e.Stderr, format, args...)
	return err
}

func (e *Env) ErrPrintln(args ...interface{}) error {
	_, err := fmt.Fprintln(e.Stderr, args...)
	return err
}
