package run

import (
	"os"
)

func FuzzArgs(data []byte) int {
	f, err := os.Create("data.conf")
	if err != nil {
		return -1
	}
	defer f.Close()
	defer os.Remove("data.conf")
	_, err = f.Write(data)
	if err != nil {
		return -1
	}
	_, err = ParseFile("data.conf", false)
	if err != nil {
		return 0
	}
	return 1
}
