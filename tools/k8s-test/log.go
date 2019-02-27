package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
)

var (
	alertColor = color.New(color.FgRed)
	warnColor  = color.New(color.FgYellow)
	goodColor  = color.New(color.FgGreen)
	infoColor  = color.New(color.FgWhite)

	// the log prefix comes from the environment
	logPrefix = func() string {
		prefix := os.Getenv("LOGPREFIX")
		if prefix != "" {
			return fmt.Sprintf("(%s) ", prefix)
		}
		return ""
	}()
)

func Infoln(format string, args ...interface{}) error {
	return logln(infoColor, os.Stdout, format, args...)
}

func Goodln(format string, args ...interface{}) error {
	return logln(goodColor, os.Stdout, format, args...)
}

func Warnln(format string, args ...interface{}) error {
	return logln(warnColor, os.Stdout, format, args...)
}

func Alertln(format string, args ...interface{}) error {
	return logln(alertColor, os.Stderr, format, args...)
}

func logln(color *color.Color, w io.Writer, format string, args ...interface{}) error {
	if _, err := infoColor.Fprintf(w, "%s[%s] ", logPrefix, time.Now().Format("15:04:05.000")); err != nil {
		return err
	}
	if _, err := color.Fprintln(w, fmt.Sprintf(format, args...)); err != nil {
		return err
	}
	return nil
}
