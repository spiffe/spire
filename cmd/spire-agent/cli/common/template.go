package common

import (
	"os"
	"strings"
)

func ResolveSocketPath(socketPath, defaultPath, templateEnv, instance string) string {
	baseEnv := strings.TrimSuffix(templateEnv, "_TEMPLATE")
	tpl := os.Getenv(templateEnv)
	sock := os.Getenv(baseEnv)
	retval := defaultPath
	if socketPath != defaultPath {
		retval = socketPath
	} else if instance != "" && strings.Contains(tpl, "%i") {
		retval = strings.ReplaceAll(tpl, "%i", instance)
	} else if sock != "" {
		retval = sock
	}
	return retval
}
