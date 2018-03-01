package util

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"runtime"

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
