package util

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
)

const flakyTestEnvKey = "SKIP_FLAKY_TESTS_UNDER_RACE_DETECTOR"

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

func SkipFlakyTestUnderRaceDetectorWithFiledIssue(t *testing.T, issue string) {
	t.Helper()
	const issuePattern = "https://github.com/spiffe/spire/issues/[[:digit:]]{4,}"
	issueRegexp := regexp.MustCompile(issuePattern)
	if !issueRegexp.Match([]byte(issue)) {
		msg := "Skip only allowed with associated issue. "
		msg += "%q does not appear to be an issue. "
		msg += "File an issue and specify it to skip a test under race detector."
		t.Fatalf(fmt.Sprintf(msg, issue))
	}
	if _, skip := os.LookupEnv(flakyTestEnvKey); skip {
		t.Skipf("Skipping under race decector until %s is resolved.", issue)
	}
}
