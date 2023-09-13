// The fflag package implements a basic singleton pattern for the purpose of
// providing SPIRE with a system-wide feature flagging facility. Feature flags
// can be easily added here, in a single central location, and be consumed
// throughout the codebase.
package fflag

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Flag represents a feature flag and its configuration name
type Flag string

// RawConfig is a list of feature flags that should be flipped on, in their string
// representations. It is loaded directly from the config file.
type RawConfig []string

// To add a feature flag, decleare it here along with its config name.
// Then, add it to the `flags` package-level singleton map below, setting the
// appropriate default value. Flags should always be opt-in and default to
// false, with the only exception being flags that are in the process of being
// deprecated.
const (
	// FlagForcedRotation controls whether or not the new APIs and
	// extensions related to forced rotation and revocation are
	// enabled or not. See #1934 for more information.
	FlagForcedRotation Flag = "forced_rotation"

	// FlagEventsBasedCache controls whether or not to use events to update the cache
	// with what's changed since the last update.
	FlagEventsBasedCache = "events_based_cache"

	// FlagReattestToRenew controls whether or not the agent will reattest to
	// renew when the SVID expires. Some attestors, such as aws_iid, are not
	// reattestable. In those cases the agent will still renew without reattesting.
	FlagReattestToRenew Flag = "reattest_to_renew"

	// FlagTestFlag is defined purely for testing purposes.
	FlagTestFlag Flag = "i_am_a_test_flag"
)

var (
	singleton = struct {
		flags  map[Flag]bool
		loaded bool
		mtx    *sync.RWMutex
	}{
		flags: map[Flag]bool{
			FlagForcedRotation:   false,
			FlagEventsBasedCache: false,
			FlagReattestToRenew:  false,
			FlagTestFlag:         false,
		},
		loaded: false,
		mtx:    new(sync.RWMutex),
	}
)

// Load initializes the fflag package and configures its feature flag state
// based on the configuration input. Feature flags are designed to be
// Write-Once-Read-Many, and as such, Load can be called only once (except when Using Unload function
// for test scenarios, which will reset states enabling Load to be called again).
// Load will return an error if it is called more than once, if the configuration input
// cannot be parsed, or if an unrecognized flag is set.
func Load(rc RawConfig) error {
	singleton.mtx.Lock()
	defer singleton.mtx.Unlock()

	if singleton.loaded {
		return errors.New("feature flags have already been loaded")
	}

	badFlags := []string{}
	goodFlags := []Flag{}
	for _, rawFlag := range rc {
		if _, ok := singleton.flags[Flag(rawFlag)]; !ok {
			badFlags = append(badFlags, rawFlag)
			continue
		}

		goodFlags = append(goodFlags, Flag(rawFlag))
	}

	if len(badFlags) > 0 {
		sort.Strings(badFlags)
		return fmt.Errorf("unknown feature flag(s): %v", badFlags)
	}

	for _, f := range goodFlags {
		singleton.flags[f] = true
	}

	singleton.loaded = true
	return nil
}

// Unload resets the feature flags states to its default values. This function is intended to be used for testing
// purposes only, it is not expected to be called by the normal execution of SPIRE.
func Unload() error {
	singleton.mtx.Lock()
	defer singleton.mtx.Unlock()

	if !singleton.loaded {
		return errors.New("feature flags have not been loaded")
	}

	for f := range singleton.flags {
		singleton.flags[f] = false
	}

	singleton.loaded = false
	return nil
}

// IsSet can be used to determine whether or not a particular feature flag is
// set.
func IsSet(f Flag) bool {
	singleton.mtx.RLock()
	defer singleton.mtx.RUnlock()

	return singleton.flags[f]
}
