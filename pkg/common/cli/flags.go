package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

// CommaStringsFlag facilitates parsing flags representing a comma separated list of strings
type CommaStringsFlag []string

func (f CommaStringsFlag) String() string {
	return strings.Join(f, ",")
}

func (f *CommaStringsFlag) Set(v string) error {
	*f = strings.Split(v, ",")
	return nil
}

// DurationFlag facilitates parsing flags representing a time.Duration
type DurationFlag time.Duration

func (f DurationFlag) String() string {
	return time.Duration(f).String()
}

func (f *DurationFlag) Set(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	*f = DurationFlag(d)
	return nil
}

// StringsFlag facilitates setting multiple flags
type StringsFlag []string

func (s *StringsFlag) String() string {
	return fmt.Sprint(*s)
}

func (s *StringsFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// BoolFlag is used to define 3 possible states: true, false, or all.
// Take care that false=1, and true=2
type BoolFlag int

const BoolFlagAll = 0
const BoolFlagFalse = 1
const BoolFlagTrue = 2

func (b *BoolFlag) String() string {
	return ""
}

func (b *BoolFlag) Set(val string) error {
	if val == "false" {
		*b = BoolFlagFalse
		return nil
	}
	if val == "true" {
		*b = BoolFlagTrue
		return nil
	}
	// if the value received isn't true or false, it will set the default value
	*b = BoolFlagAll
	return nil
}

// StringVar registers a string flag with an optional shorthand.
func StringVar(f *flag.FlagSet, p *string, name, shorthand, value, usage string) {
	f.StringVar(p, name, value, usage)
	if shorthand != "" {
		f.StringVar(p, shorthand, value, usage)
	}
}

// BoolVar registers a bool flag with an optional shorthand.
func BoolVar(f *flag.FlagSet, p *bool, name, shorthand string, value bool, usage string) {
	f.BoolVar(p, name, value, usage)
	if shorthand != "" {
		f.BoolVar(p, shorthand, value, usage)
	}
}

// IntVar registers an int flag with an optional shorthand.
func IntVar(f *flag.FlagSet, p *int, name, shorthand string, value int, usage string) {
	f.IntVar(p, name, value, usage)
	if shorthand != "" {
		f.IntVar(p, shorthand, value, usage)
	}
}

// Int64Var registers an int64 flag with an optional shorthand.
func Int64Var(f *flag.FlagSet, p *int64, name, shorthand string, value int64, usage string) {
	f.Int64Var(p, name, value, usage)
	if shorthand != "" {
		f.Int64Var(p, shorthand, value, usage)
	}
}

// Var registers a flag.Value with an optional shorthand.
func Var(f *flag.FlagSet, value flag.Value, name, shorthand, usage string) {
	f.Var(value, name, usage)
	if shorthand != "" {
		f.Var(value, shorthand, usage)
	}
}
