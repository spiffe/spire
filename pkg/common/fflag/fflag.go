// The fflag package implements a basic singleton pattern for the purpose of
// providing SPIRE with a system-wide feature flagging facility. Feature flags
// can be easily added here, in a single central location, and be consumed
// throughout the codebase.
package fflag

import (
	"errors"
	"fmt"
	"sync"
)

// Flag represents a feature flag and its configuration name
type Flag string

// To add a feature flag, decleare it here along with its config name.
// Then, add it to the `flags` package-level singleton map below, setting the
// appropriate default value. Flags should always be opt-in and default to
// false, with the only exception being flags that are in the process off being
// deprecated.
const (
	// FlagForcedRotation controls whether or not the new APIs and
	// extensions related to forced rotation and revocation are
	// enabled or not. See #1934 for more information.
	FlagForcedRotation Flag = "forced_rotation"

	// FlagTestFlag is defined purely for testing purposes.
	FlagTestFlag Flag = "i_am_a_test_flag"
)

var (
	singleton = struct {
		flags  map[Flag]bool
		loaded *sync.Once
		mtx    *sync.RWMutex
	}{
		flags: map[Flag]bool{
			FlagForcedRotation: false,
			FlagTestFlag:       false,
		},
		loaded: new(sync.Once),
		mtx:    new(sync.RWMutex),
	}
)

// Load initializes the fflag package and configures its feature flag state
// based on the configuration input. Feature flags are designed to be
// Write-Once-Read-Many, and as such, Load can be called only once. Load will
// return an error if it is called more than once, if the configuration input
// cannot be parsed, or if an unrecognized flag is set.
func Load(rc RawConfig) error {
	flagConfig, err := parseRawConfig(rc)
	if err != nil {
		return err
	}

	err = validateFlags(flagConfig)
	if err != nil {
		return err
	}

	ok := false
	singleton.loaded.Do(func() {
		ok = true
		load(flagConfig)
	})

	if !ok {
		return errors.New("feature flags have already been loaded")
	}

	return nil
}

// IsSet can be used to determine whether or not a particular feature flag is
// set.
func IsSet(f Flag) bool {
	singleton.mtx.RLock()
	defer singleton.mtx.RUnlock()

	return singleton.flags[f]
}

func load(flagConfig map[string]bool) {
	singleton.mtx.Lock()
	defer singleton.mtx.Unlock()

	for flag, _ := range singleton.flags {
		if value, ok := flagConfig[string(flag)]; ok {
			singleton.flags[flag] = value
		}
	}
}

func validateFlags(flagConfig map[string]bool) error {
	badFlags := make(map[string]bool)
	for name, _ := range flagConfig {
		badFlags[name] = true
	}

	singleton.mtx.RLock()
	for flag, _ := range singleton.flags {
		if _, ok := badFlags[string(flag)]; ok {
			badFlags[string(flag)] = false
		}
	}
	singleton.mtx.RUnlock()

	badNames := []string{}
	for name, bad := range badFlags {
		if bad {
			badNames = append(badNames, name)
		}
	}

	if len(badNames) > 0 {
		return fmt.Errorf("unknown feature flag(s): %v", badNames)
	}

	return nil
}
