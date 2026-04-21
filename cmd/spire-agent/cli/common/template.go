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
			return "", fmt.Errorf("You must define %s to use the instance flag", templateEnv)
		} else if !strings.Contains(tpl, "%i")  {
			return "", fmt.Errorf("Failed to find %%i in %s", templateEnv)
		}
	}
	retval := defaultPath
	if socketPath != defaultPath {
		retval = socketPath
	} else if instance != "" {
		retval = strings.ReplaceAll(tpl, "%i", instance)
	} else if sock != "" {
		retval = sock
	}
	return retval, nil
}
