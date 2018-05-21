package version

import "fmt"

const (
	Base = "0.0.1"
)

var (
	githash = ""
)

func Version() string {
	if githash == "" {
		return fmt.Sprintf("%s-dev", Base)
	}
	return fmt.Sprintf("%s (%s)", Base, githash)
}
