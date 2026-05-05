package common

import (
	"fmt"
	"os"
	"strings"
)

func ResolveSocketPath(socketPath, defaultPath, templateEnv, instance string) (string, error) {
	baseEnv := strings.TrimSuffix(templateEnv, "_TEMPLATE")
	tpl := os.Getenv(templateEnv)
	sock := os.Getenv(baseEnv)
	if instance != "" {
		if tpl == "" {
			return "", fmt.Errorf(" %s environment variable must be defined when using the instance flag", templateEnv)
		}
		if !strings.Contains(tpl, "%i") {
			return "", fmt.Errorf("failed to find %%i in %s", templateEnv)
		}
	}
	var retval string
	switch {
	case socketPath != defaultPath:
		retval = socketPath
	case instance != "":
		retval = strings.ReplaceAll(tpl, "%i", instance)
	case sock != "":
		retval = sock
	default:
		retval = defaultPath
	}
	return retval, nil
}
