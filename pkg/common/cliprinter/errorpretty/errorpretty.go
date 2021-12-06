package errorpretty

import (
	"errors"
	"fmt"
	"io"
)

func Print(err error, _, stderr io.Writer) bool {
	if err == nil {
		return true
	}

	if err.Error() == "" {
		err = errors.New("An unknown error occurred")
	}

	_, e := fmt.Fprintln(stderr, err.Error())
	if e != nil {
		return false
	}

	return true
}
