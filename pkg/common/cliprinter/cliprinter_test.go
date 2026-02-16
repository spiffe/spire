package cliprinter

import (
	"bytes"
	"errors"
	"io"
	"testing"

	agentapi "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

func TestPrintError(t *testing.T) {
	p, stdout, stderr := newTestPrinter()

	err := p.PrintError(errors.New("red alert"))
	if err != nil {
		t.Errorf("failed to print error: %v", err)
	}

	if stdout.Len() == 0 {
		t.Error("did not print error")
	}

	if stderr.Len() > 0 {
		t.Errorf("error printed on stderr")
	}

	p = newTestPrinterWithWriter(badWriter{}, badWriter{})
	err = p.PrintError(errors.New("red alert"))
	if err == nil {
		t.Errorf("did not return error after bad write")
	}
}

func TestPrintProto(t *testing.T) {
	p, stdout, stderr := newTestPrinter()

	err := p.PrintProto(new(agentapi.CountAgentsResponse))
	if err != nil {
		t.Errorf("failed to print proto: %v", err)
	}
	if stderr.Len() > 0 {
		t.Errorf("error while printing protobuf: %q", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("did not print protobuf")
	}

	p = newTestPrinterWithWriter(badWriter{}, badWriter{})
	err = p.PrintProto(new(agentapi.CountAgentsResponse))
	if err == nil {
		t.Errorf("did not return error after bad write")
	}
}

func TestPrintStruct(t *testing.T) {
	p, stdout, stderr := newTestPrinter()

	msg := struct {
		Name string
	}{
		Name: "boaty",
	}

	err := p.PrintStruct(msg)
	if err != nil {
		t.Errorf("failed to print struct: %v", err)
	}

	if stderr.Len() > 0 {
		t.Errorf("error while printing struct: %q", stderr.String())
	}

	if stdout.Len() == 0 {
		t.Error("did not print struct")
	}

	expectedOutput := "Name: boaty\n\n"
	actualOutput := stdout.String()
	if actualOutput != expectedOutput {
		t.Errorf("output expected to be %q but got %q", expectedOutput, actualOutput)
	}

	p = newTestPrinterWithWriter(badWriter{}, badWriter{})
	err = p.PrintStruct(msg)
	if err == nil {
		t.Errorf("did not return error after bad write")
	}
}

func newTestPrinter() (p *printer, stdout, stderr *bytes.Buffer) {
	stdout = new(bytes.Buffer)
	stderr = new(bytes.Buffer)

	return newTestPrinterWithWriter(stdout, stderr), stdout, stderr
}

func newTestPrinterWithWriter(stdout, stderr io.Writer) *printer {
	if stdout == nil {
		stdout = new(bytes.Buffer)
	}

	if stderr == nil {
		stderr = new(bytes.Buffer)
	}
	env := &commoncli.Env{
		Stdout: stdout,
		Stderr: stderr,
	}

	return newPrinter(defaultFormatType, env)
}

type badWriter struct{}

func (badWriter) Write(_ []byte) (int, error) { return 0, errors.New("red alert") }
