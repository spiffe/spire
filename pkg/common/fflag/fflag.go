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

// To add a feature flag, declare it in `common.go`, `agent.go`, or
// `server.go` depending on where it should be considered valid. Then,
// add it to the relevant package-level map, setting the appropriate
// default value. Common feature flags are added to the map in `common.go`,
// while agent or server specific flags are added to the map in the `afflag` or
// `sfflag` package, located in the agent or server codebase, respectively.
// Flags should always be opt-in, and default to false, with the only exception
// being flags that are in the process of being deprecated.
var (
	singleton = struct {
		flags  map[Flag]bool
		loaded *sync.Once
		mtx    *sync.RWMutex
	}{
		flags:  commonFlagMap,
		loaded: new(sync.Once),
		mtx:    new(sync.RWMutex),
	}
)

// Load initializes the fflag package and configures its feature flag state
// based on the configuration input. Feature flags are designed to be
// Write-Once-Read-Many, and as such, Load can be called only once. Load will
// return an error if it is called more than once, if the configuration input
// cannot be parsed, or if an unrecognized flag is set.
func Load(rc RawConfig, supplementalFlags map[Flag]bool) error {
	flagConfig, err := parseRawConfig(rc)
	if err != nil {
		return fmt.Errorf("could not parse feature flag configuration: %w", err)
	}

	err = validateFlags(flagConfig, supplementalFlags)
	if err != nil {
		return fmt.Errorf("bad feature flag configuration: %w", err)
	}

	ok := false
	singleton.loaded.Do(func() {
		ok = true
		load(flagConfig, supplementalFlags)
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

func load(flagConfig map[string]bool, supplementalFlags map[Flag]bool) {
	singleton.mtx.Lock()
	defer singleton.mtx.Unlock()

	for f, v := range supplementalFlags {
		// Common flags should take precedent
		if _, ok := singleton.flags[f]; ok {
			continue
		}

		singleton.flags[f] = v
	}

	for flag := range singleton.flags {
		if value, ok := flagConfig[string(flag)]; ok {
			singleton.flags[flag] = value
		}
	}
}

func validateFlags(flagConfig map[string]bool, supplementalFlags map[Flag]bool) error {
	badFlags := make(map[string]bool)
	for name := range flagConfig {
		badFlags[name] = true
	}

	for flag := range supplementalFlags {
		if _, ok := badFlags[string(flag)]; ok {
			badFlags[string(flag)] = false
		}
	}

	singleton.mtx.RLock()
	for flag := range singleton.flags {
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
