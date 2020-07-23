package version

import "fmt"

const (
	// Base is the base version for the codebase.
	//
	// IMPORTANT: When updating, make sure to reconcile the versions list that
	// is part of the upgrade integration test. See
	// test/integration/suites/upgrade/README.md for details.
	Base = "0.11.0"
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
