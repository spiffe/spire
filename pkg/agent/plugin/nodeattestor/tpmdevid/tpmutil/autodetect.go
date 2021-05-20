package tpmutil

import (
	"errors"
	"io/ioutil"
	"path"
	"regexp"
)

var validTPMNames = []*regexp.Regexp{
	regexp.MustCompile(`tpmrm\d+$`),
	regexp.MustCompile(`tpm\d+$`),
}

func AutoDetectTPMPath(baseTPMDir string) (string, error) {
	files, err := ioutil.ReadDir(baseTPMDir)
	if err != nil {
		return "", err
	}

	for _, validExp := range validTPMNames {
		for _, f := range files {
			if validExp.MatchString(f.Name()) {
				candidateTPM := path.Join(baseTPMDir, f.Name())
				if isValidTPM(candidateTPM) {
					return candidateTPM, nil
				}
			}
		}
	}

	return "", errors.New("unable to autodetect TPM")
}

// VerifyTPM verifies that the given path belongs to a functional TPM 2.0
func isValidTPM(path string) bool {
	rwc, err := OpenTPM(path)
	if err != nil {
		return false
	}
	defer rwc.Close()

	return true
}
