package cliprinter

import (
	"io"
	"os"

	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter/internal/errorjson"
	"github.com/spiffe/spire/pkg/common/cliprinter/internal/errorpretty"
	"github.com/spiffe/spire/pkg/common/cliprinter/internal/protojson"
	"github.com/spiffe/spire/pkg/common/cliprinter/internal/protopretty"
	"github.com/spiffe/spire/pkg/common/cliprinter/internal/structjson"
	"github.com/spiffe/spire/pkg/common/cliprinter/internal/structpretty"
	"google.golang.org/protobuf/proto"
)

// Printer is an interface for providing a printer implementation to
// a CLI utility.
type Printer interface {
	MustPrintError(error)
	MustPrintProto(...proto.Message)
	MustPrintStruct(...interface{})
}

// CustomPrettyFunc is used to provide a custom function for pretty
// printing messages. The intent is to provide a migration pathway
// for pre-existing CLI code, such that this code can supply a
// custom pretty printer that mirrors its current behavior, but
// still be able to gain formatter functionality for other outputs.
type CustomPrettyFunc func(*commoncli.Env, ...interface{}) error

type printer struct {
	format formatType
	env    *commoncli.Env
	cp     CustomPrettyFunc
}

func newPrinter(f formatType, env *commoncli.Env) *printer {
	if env == nil {
		env = commoncli.DefaultEnv
	}
	return &printer{
		format: f,
		env:    env,
	}
}

// MustPrintError prints an error and applies the configured formatting. If
// an error is encountered while printing, MustPrintError will call os.Exit(2).
func (p *printer) MustPrintError(err error) {
	if err := p.printError(err); err != nil {
		os.Exit(2)
	}
}

// PrintProto prints a protobuf message and applies the configured formatting. If
// an error is encountered while printing, MustPrintProto will call os.Exit(2).
func (p *printer) MustPrintProto(msg ...proto.Message) {
	if err := p.printProto(msg...); err != nil {
		os.Exit(2)
	}
}

// PrintStruct prints a struct and applies the configured formatting. If
// an error is encountered while printing, MustPrintStruct will call os.Exit(2).
func (p *printer) MustPrintStruct(msg ...interface{}) {
	if err := p.printStruct(msg); err != nil {
		os.Exit(2)
	}
}

func (p *printer) printError(err error) error {
	switch p.format {
	case json:
		return errorjson.Print(err, p.env.Stdout, p.env.Stderr)
	default:
		return p.printPrettyError(err, p.env.Stdout, p.env.Stderr)
	}
}

func (p *printer) printProto(msg ...proto.Message) error {
	switch p.format {
	case json:
		return protojson.Print(msg, p.env.Stdout, p.env.Stderr)
	default:
		return p.printPrettyProto(msg, p.env.Stdout, p.env.Stderr)
	}
}

func (p *printer) printStruct(msg ...interface{}) error {
	switch p.format {
	case json:
		return structjson.Print(msg, p.env.Stdout, p.env.Stderr)
	default:
		return p.printPrettyStruct(msg, p.env.Stdout, p.env.Stderr)
	}
}

func (p *printer) getFormat() formatType {
	return p.format
}

func (p *printer) setCustomPrettyPrinter(cp CustomPrettyFunc) {
	p.cp = cp
}

func (p *printer) printPrettyError(err error, stdout, stderr io.Writer) error {
	if p.cp != nil {
		return p.cp(p.env, err)
	}

	return errorpretty.Print(err, stdout, stderr)
}
func (p *printer) printPrettyProto(msgs []proto.Message, stdout, stderr io.Writer) error {
	if p.cp != nil {
		m := []interface{}{}
		for _, msg := range msgs {
			m = append(m, msg.(interface{}))
		}

		return p.cp(p.env, m...)
	}

	return protopretty.Print(msgs, stdout, stderr)
}
func (p *printer) printPrettyStruct(msg []interface{}, stdout, stderr io.Writer) error {
	if p.cp != nil {
		return p.cp(p.env, msg...)
	}

	return structpretty.Print(msg, stdout, stderr)
}
