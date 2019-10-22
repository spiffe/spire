package version

import "fmt"

const (
	Base = "0.9.0"
)

var (
	gittag  = ""
	githash = "unk"
)

func Version() string {
	if gittag == "" {
		return fmt.Sprintf("%s-dev-%s", Base, githash)
	}
	return gittag
}
