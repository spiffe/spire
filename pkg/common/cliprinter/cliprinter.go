package cliprinter

import (
	"errors"
	"io"

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
	PrintError(error) error
	PrintProto(...proto.Message) error
	PrintStruct(...interface{}) error
}

// CustomPrettyFunc is used to provide a custom function for pretty
// printing messages. The intent is to provide a migration pathway
// for pre-existing CLI code, such that this code can supply a
// custom pretty printer that mirrors its current behavior, but
// still be able to gain formatter functionality for other outputs.
type CustomPrettyFunc func(*commoncli.Env, ...interface{}) error

// ErrInternalCustomPrettyFunc should be returned by a CustomPrettyFunc when some internal error occurs.
var ErrInternalCustomPrettyFunc = errors.New("internal error: cli printer; please report this bug")

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

// PrintError prints an error and applies the configured formatting.
func (p *printer) PrintError(err error) error {
	return p.printError(err)
}

// PrintProto prints a protobuf message and applies the configured formatting.
func (p *printer) PrintProto(msg ...proto.Message) error {
	return p.printProto(msg...)
}

// PrintStruct prints a struct and applies the configured formatting.
func (p *printer) PrintStruct(msg ...interface{}) error {
	return p.printStruct(msg)
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
