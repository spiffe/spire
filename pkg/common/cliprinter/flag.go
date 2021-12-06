package cliprinter

import (
	"errors"
	"flag"
	"fmt"
)

// AppendFlag adds the -format flag to the provided flagset, and populates
// the referenced Printer interface with a properly configured printer.
func AppendFlag(p *Printer, fs *flag.FlagSet) {
	AppendFlagWithCustomPretty(p, fs, nil)
}

// AppendFlagWithCustomPretty is the same as AppendFlag, however it also allows
// a custom pretty function to be specified. A custom pretty function can be used
// to override the pretty print logic that normally ships with this package. Its
// intended use is to allow for the adoption of cliprinter while still retaining
// backwards compatibility with the legacy/bespoke pretty print output.
func AppendFlagWithCustomPretty(p *Printer, fs *flag.FlagSet, cp CustomPrettyFunc) {
	// Set the default
	np := newPrinter(defaultFormatType)
	np.setCustomPrettyPrinter(cp)
	*p = np

	f := &FormatterFlag{
		p:            p,
		customPretty: cp,
	}

	fs.Var(f, "format", "Desired output format (pretty, json)")
}

type FormatterFlag struct {
	customPretty func(...interface{})

	// A pointer to our consumer's Printer interface
	p *Printer
}

func (f *FormatterFlag) String() string {
	return "pretty"
}

func (f *FormatterFlag) Set(formatStr string) error {
	if f.p == nil {
		return errors.New("internal error: formatter flag not correctly invoked; please report this bug")
	}

	format, err := strToFormatType(formatStr)
	if err != nil {
		return fmt.Errorf("bad formatter flag: %v", err)
	}

	np := newPrinter(format)
	np.setCustomPrettyPrinter(f.customPretty)

	*f.p = np
	return nil
}
