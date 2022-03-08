package tpmutil

import (
	"errors"
	"os"
	"path"
	"regexp"
)

var validTPMNames = []*regexp.Regexp{
	regexp.MustCompile(`tpmrm\d+$`),
	regexp.MustCompile(`tpm\d+$`),
}

func AutoDetectTPMPath(baseTPMDir string) (string, error) {
	files, err := os.ReadDir(baseTPMDir)
	if err != nil {
		return "", err
	}

	for _, validExp := range validTPMNames {
		var deviceFound bool
		var tpmDevicePath string

		for _, f := range files {
			deviceNameMatch := validExp.MatchString(f.Name())

			switch {
			case deviceNameMatch && !deviceFound:
				tpmDevicePath = path.Join(baseTPMDir, f.Name())
				deviceFound = true
				// Do not return yet, we need to make sure that
				// there is only one TPM device.

			case deviceNameMatch && deviceFound:
				return "", errors.New("more than one possible TPM device was found")

			default:
			}
		}

		if deviceFound {
			return tpmDevicePath, nil
		}
	}

	return "", errors.New("not found")
}
