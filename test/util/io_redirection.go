package util

import (
	"bytes"
	"errors"
	"io"
	"os"
)

const (
	stdout kind = iota
	stderr
)

type kind int

type OutputRedirection struct {
	kind           kind
	originalOutput *os.File
	pipeR          *os.File
	pipeW          *os.File
}

func (redirector *OutputRedirection) Start(output *os.File) error {
	if output != os.Stdout && output != os.Stderr {
		return errors.New("invalid value for output parameter")
	}

	redirector.originalOutput = output
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	redirector.pipeR = r
	redirector.pipeW = w

	switch output {
	case os.Stdout:
		os.Stdout = w
		redirector.kind = stdout
	case os.Stderr:
		os.Stderr = w
		redirector.kind = stderr
	}

	return nil
}

func (redirector *OutputRedirection) Finish() (string, error) {
	var errorReading error
	output := make(chan string)

	go func() {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, redirector.pipeR)
		if err != nil {
			errorReading = err
			output <- ""
			return
		}
		redirector.pipeR.Close()
		output <- buf.String()
	}()

	redirector.pipeW.Close()
	switch redirector.kind {
	case stdout:
		os.Stdout = redirector.originalOutput
	case stderr:
		os.Stderr = redirector.originalOutput
	}

	result := <-output

	return result, errorReading
}
