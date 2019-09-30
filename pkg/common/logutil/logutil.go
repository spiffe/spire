package logutil

import (
	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
	"strings"
	"unicode"
)

// Log the message in the provided error to the designated logger Error stream
// with the first character of the message in uppercase.
func LogError(logger logrus.FieldLogger, err error) {
	if err == nil {
		return
	}
	LogErrorStr(logger, err.Error())
}

// Log the provided error string to the designated logger Error stream
// with the first character of the message in uppercase.
func LogErrorStr(logger logrus.FieldLogger, errorStr string) {
	capitalizedErr := capitalize(errorStr)
	logger.Error(capitalizedErr)
}

// Log the message in the provided error to the designated plugin logger Error stream
// with the first character of the message in uppercase.
func LogPluginError(logger hclog.Logger, err error) {
	if err == nil {
		return
	}
	LogPluginErrorStr(logger, err.Error())
}

// Log the provided error string to the designated plugin logger Error stream
// with the first character of the message in uppercase.
func LogPluginErrorStr(logger hclog.Logger, errorStr string) {
	capitalizedErr := capitalize(errorStr)
	logger.Error(capitalizedErr)
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}

	capital, secondIndex := capitalizedFirstRune(s)
	var sb strings.Builder
	sb.WriteRune(capital)
	sb.WriteString(s[secondIndex:])
	return sb.String()
}

// Return the uppercase version of the first UTF-8 rune in the string s
// and the index of the second rune in the underlying string byte array.
func capitalizedFirstRune(s string) (rune, int) {
	var first rune
	isFirst := true
	secondIndex := len(s)
	for i, c := range s {
		if isFirst {
			first = c
			isFirst = false
		} else {
			secondIndex = i
			break
		}
	}

	return unicode.ToUpper(first), secondIndex
}
