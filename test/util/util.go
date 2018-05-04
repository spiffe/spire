package util

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/spiffe/spire/proto/common"
)

// ProjectRoot returns the absolute path to the SPIRE project root
func ProjectRoot() string {
	_, p, _, _ := runtime.Caller(0)
	return path.Join(p, "../../../")
}

//GetRegistrationEntries gets registration entries from a fixture
func GetRegistrationEntries(fileName string) []*common.RegistrationEntry {
	regEntries := &common.RegistrationEntries{}
	path := path.Join(ProjectRoot(), "test/fixture/registration/", fileName)
	dat, _ := ioutil.ReadFile(path)
	json.Unmarshal(dat, &regEntries)
	return regEntries.Entries
}

//GetRegistrationEntriesMap gets a map of registration entries from a fixture
func GetRegistrationEntriesMap(fileName string) map[string][]*common.RegistrationEntry {
	regEntriesMap := map[string]*common.RegistrationEntries{}
	path := path.Join(ProjectRoot(), "test/fixture/registration/", fileName)
	dat, _ := ioutil.ReadFile(path)
	json.Unmarshal(dat, &regEntriesMap)
	result := map[string][]*common.RegistrationEntry{}
	for key, regEntries := range regEntriesMap {
		result[key] = regEntries.Entries
	}
	return result
}

// RunWithTimeout runs code within the specified timeout, if execution
// takes longer than that, an error is logged to t with information
// about the caller of this function. Returns how much time it took to
// run the function.
func RunWithTimeout(t *testing.T, timeout time.Duration, code func()) time.Duration {
	_, file, line, _ := runtime.Caller(1)

	done := make(chan struct{})
	ti := time.NewTicker(timeout)
	start := time.Now()
	go func() {
		code()
		close(done)
	}()

	select {
	case <-ti.C:
		t.Errorf("%s:%d: code execution took more than %v", file, line, timeout)
		return time.Since(start)
	case <-done:
		return time.Since(start)
	}
}
