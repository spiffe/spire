package telemetry

import (
	"regexp"
)

const (
	// Choice of replacement character is detailed with regex.
	_replaceChar = "_"
)

var (
	// For statsd, valid characters are [a-zA-Z0-9_.].
	// For prometheus, valid characters are [a-zA-Z0-9:_].
	// Generally, `.` is used as a delimiter on metric namespaces
	// in telemetry systems.
	// It seems unlikely any metrics system would make any alphanumeric
	// character be invalid, and `_` seems to be consistently allowed.
	// Therefore, safest characters are [a-zA-Z0-9_], which is \w in
	// regex, the opposite being \W.
	// Since `_` has no inherent meaning compared to alphanumeric,
	// and is the only safe non-alphanumeric character left, it is a
	// suitable replacement character when sanitizing metrics.
	// We wind up with `\W+`, but we also want to avoid adjacent `_`
	// for cleanliness, so to merge sanitized characters with possible
	// trailing `_`, add `_?`.
	_invalidCharsRegex = regexp.MustCompile(`\W+_?`)
)

// sanitizeLabel takes the input string and replaces all groups of
// invalid characters with the valid replacement character.
func sanitizeLabel(val string) string {
	return _invalidCharsRegex.ReplaceAllString(val, _replaceChar)
}

// getSanitizedLabel take the input name and value, sanitize the
// name and value, and return the resulting telemetry label.
func getSanitizedLabel(name, val string) Label {
	return Label{
		Name:  sanitizeLabel(name),
		Value: sanitizeLabel(val),
	}
}

// GetSanitizedLabels sanitize all given labels
func GetSanitizedLabels(labels []Label) []Label {
	sanitizedLabels := make([]Label, len(labels))
	for i, label := range labels {
		sanitizedLabels[i] = getSanitizedLabel(label.Name, label.Value)
	}

	return sanitizedLabels
}
