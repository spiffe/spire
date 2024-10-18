package config

import (
	"os"
)

func ExpandEnv(data string) string {
	return os.Expand(data, func(key string) string {
		if key == "$" {
			return "$"
		}
		return os.Getenv(key)
	})
}
