package util

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

var (
	raceTestNumThreads = 2
	raceTestNumLoops   = 2
)

func init() {
	raceTestNumThreads = getEnvInt("SPIRE_TEST_RACE_NUM_THREADS", raceTestNumThreads)
	raceTestNumLoops = getEnvInt("SPIRE_TEST_RACE_NUM_LOOPS", raceTestNumLoops)
}

func RaceTest(t *testing.T, fn func(*testing.T)) {
	// wrap in a top level group to ensure all subtests
	// complete before this method returns. All subtests
	// will be run in parallel
	t.Run("group", func(t *testing.T) {
		for i := 0; i < raceTestNumThreads; i++ {
			t.Run(fmt.Sprintf("thread %v", i), func(t *testing.T) {
				t.Parallel()
				for i := 0; i < raceTestNumLoops; i++ {
					fn(t)
				}
			})
		}
	})
}

func getEnvInt(name string, fallback int) int {
	if env := os.Getenv(name); env != "" {
		val, err := strconv.Atoi(env)
		if err != nil {
			panic(fmt.Sprintf("%v invalid value: %v", name, err))
		}
		return val
	}
	return fallback
}
