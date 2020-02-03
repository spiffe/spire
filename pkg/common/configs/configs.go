package configs

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
)

// Render renders a text template of a configuration file.
func Render(text string) (string, error) {
	parsed, err := template.New("").Funcs(map[string]interface{}{"env": getEnv}).Parse(text)
	if err != nil {
		return "", fmt.Errorf("error parsing template: [%s]", err.Error())
	}

	var buffer bytes.Buffer

	err = parsed.Execute(&buffer, nil)
	if err != nil {
		return "", fmt.Errorf("error executing template: [%s]", err.Error())
	}

	return buffer.String(), nil
}

// getEnv returns the value of an environment variable or an empty string if unset.
func getEnv(key string) string {
	return os.Getenv(key)
}
