package diskutil

import (
	"io/ioutil"
	"os"
)

func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := ioutil.WriteFile(path+".tmp", data, mode); err != nil {
		return err
	}

	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}

	return nil
}
