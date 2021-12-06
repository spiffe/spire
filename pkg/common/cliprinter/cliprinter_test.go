package cliprinter

import (
	"bytes"
	"errors"
	"testing"

	agentapi "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
)

func TestPrintError(t *testing.T) {
	p, stdout, stderr := newTestPrinter()

	err := errors.New("red alert")
	p.PrintError(err)

	if stdout.Len() > 0 {
		t.Errorf("error printed on stdout")
	}

	if stderr.Len() == 0 {
		t.Error("did not print error")
	}
}

func TestPrintProto(t *testing.T) {
	p, stdout, stderr := newTestPrinter()

	p.PrintProto(new(agentapi.CountAgentsResponse))
	if stderr.Len() > 0 {
		t.Errorf("error while printing protobuf: %q", stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("did not print protobuf")
	}
}

func TestPrintStruct(t *testing.T) {
	p, stdout, stderr := newTestPrinter()

	msg := struct {
		Name string
	}{
		Name: "boaty",
	}

	p.PrintStruct(msg)

	if stderr.Len() > 0 {
		t.Errorf("error while printing struct: %q", stderr.String())
	}

	if stdout.Len() == 0 {
		t.Error("did not print struct")
	}
}

func newTestPrinter() (p *printer, stdout, stderr *bytes.Buffer) {
	stdout = new(bytes.Buffer)
	stderr = new(bytes.Buffer)
	p = newPrinter(pretty)
	p.stdout = stdout
	p.stderr = stderr

	return p, stdout, stderr
}
