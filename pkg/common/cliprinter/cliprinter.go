package cliprinter

import (
	"io"
	"os"

	"github.com/spiffe/spire/pkg/common/cliprinter/errorjson"
	"github.com/spiffe/spire/pkg/common/cliprinter/errorpretty"
	"github.com/spiffe/spire/pkg/common/cliprinter/protojson"
	"github.com/spiffe/spire/pkg/common/cliprinter/protopretty"
	"github.com/spiffe/spire/pkg/common/cliprinter/structjson"
	"github.com/spiffe/spire/pkg/common/cliprinter/structpretty"
	"google.golang.org/protobuf/proto"
)

type Printer interface {
	MustPrintError(error)
	MustPrintProto(...proto.Message)
	MustPrintStruct(...interface{})

	PrintError(error)
	PrintProto(...proto.Message)
	PrintStruct(...interface{})
}

type CustomPrettyFunc func(...interface{})

type printer struct {
	format formatType

	stdout io.Writer
	stderr io.Writer

	cp CustomPrettyFunc
}

func newPrinter(f formatType) *printer {
	return &printer{
		format: f,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
}

// PrintError prints an error and applies the configured formatting
func (p *printer) PrintError(err error) {
	p.printError(err)
}

// PrintProto prints a protobuf message and applies the configured formatting
func (p *printer) PrintProto(msg ...proto.Message) {
	p.printProto(msg...)
}

// PrintStruct prints a struct and applies the configured formatting
func (p *printer) PrintStruct(msg ...interface{}) {
	p.printStruct(msg...)
}

// MustPrintError prints an error and applies the configured formatting. If
// an error is encountered while printing, MustPrintError will call os.Exit(2).
func (p *printer) MustPrintError(err error) {
	if ok := p.printError(err); !ok {
		os.Exit(2)
	}
}

// PrintProto prints a protobuf message and applies the configured formatting. If
// an error is encountered while printing, MustPrintProto will call os.Exit(2).
func (p *printer) MustPrintProto(msg ...proto.Message) {
	if ok := p.printProto(msg...); !ok {
		os.Exit(2)
	}
}

// PrintStruct prints a struct and applies the configured formatting. If
// an error is encountered while printing, MustPrintStruct will call os.Exit(2).
func (p *printer) MustPrintStruct(msg ...interface{}) {
	if ok := p.printStruct(msg); !ok {
		os.Exit(2)
	}
}

func (p *printer) printError(err error) bool {
	switch p.format {
	case json:
		return errorjson.Print(err, p.stdout, p.stderr)
	default:
		p.printPrettyError(err, p.stdout, p.stderr)
		return true
	}
}

func (p *printer) printProto(msg ...proto.Message) bool {
	switch p.format {
	case json:
		return protojson.Print(msg, p.stdout, p.stderr)
	default:
		p.printPrettyProto(msg, p.stdout, p.stderr)
		return true
	}
}

func (p *printer) printStruct(msg ...interface{}) bool {
	switch p.format {
	case json:
		return structjson.Print(msg, p.stdout, p.stderr)
	default:
		p.printPrettyStruct(msg, p.stdout, p.stderr)
		return true
	}
}

func (p *printer) getFormat() formatType {
	return p.format
}

func (p *printer) setCustomPrettyPrinter(cp CustomPrettyFunc) {
	p.cp = cp
}

func (p *printer) printPrettyError(err error, stdout, stderr io.Writer) {
	if !p.printCustomPretty([]interface{}{err}) {
		errorpretty.Print(err, stdout, stderr)
	}
}
func (p *printer) printPrettyProto(msg []proto.Message, stdout, stderr io.Writer) {
	if !p.printCustomPretty([]interface{}{msg}) {
		protopretty.Print(msg, stdout, stderr)
	}
}
func (p *printer) printPrettyStruct(msg []interface{}, stdout, stderr io.Writer) {
	if !p.printCustomPretty(msg) {
		structpretty.Print(msg, stdout, stderr)
	}
}

// printCustomPretty will print a message using the configured custom pretty
// hook. If a custom pretty function is not set, this function will return
// false.
func (p *printer) printCustomPretty(msg []interface{}) bool {
	if p.cp != nil {
		p.cp(msg)
		return true
	}

	return false
}
