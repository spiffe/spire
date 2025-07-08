package errorpretty

import (
	"errors"
	"fmt"
	"io"
)

func Print(err error, stdout, _ io.Writer) error {
	if err == nil {
		return nil
	}

	if err.Error() == "" {
		err = errors.New("an unknown error occurred")
	}

	_, e := fmt.Fprintln(stdout, err.Error())
	return e
}
