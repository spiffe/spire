package cli

import (
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
