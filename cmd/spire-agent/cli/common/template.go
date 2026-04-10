package common

import (
    "os"
    "strings"
)

func ResolveSocketPath(socketPath, defaultPath, templateEnv, instance string) string {
    tpl := os.Getenv(templateEnv)
    if tpl != "" && strings.Contains(tpl, "%i") {
        if instance == "" {
            instance = "main"
        }
        if socketPath == "" || socketPath == defaultPath {
            return strings.ReplaceAll(tpl, "%i", instance)
        }
    }
    if socketPath == "" {
        return defaultPath
    }
    return socketPath
}
