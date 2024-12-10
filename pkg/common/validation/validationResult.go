package validation

import (
	"errors"
	"fmt"
)

/* Captures the result of a configuration validation */
// TODO: make ValidationError validationError
// TODO: make ValidationNotes validationNotes
type ValidationResult struct {
	ValidationError string    `json:"error"`
	ValidationNotes []string  `json:"notes"`
}

func (v *ValidationResult) Error() error {
	if v.ValidationError != "" {
		return errors.New(v.ValidationError)
	}
	return nil
}

func (v *ValidationResult) HasError() bool {
	return v.ValidationError != ""
}

func (v *ValidationResult) ReportError(message string) {
	if v.ValidationError == "" {
		v.ValidationError = message
	}
	v.ValidationNotes = append(v.ValidationNotes, message)
}

func (v *ValidationResult) ReportErrorf(format string, params ...any) {
	v.ReportError(fmt.Sprintf(format, params...))
}

func (v *ValidationResult) ReportInfo(message string) {
	v.ValidationNotes = append(v.ValidationNotes, message)
}

func (v *ValidationResult) ReportInfof(format string, params ...any) {
	v.ReportInfo(fmt.Sprintf(format, params...))
}

func (v *ValidationResult) Merge(other ValidationResult) {
	if v.ValidationError == "" {
		v.ValidationError = other.ValidationError
	}
	v.ValidationNotes = append(v.ValidationNotes, other.ValidationNotes...)
}

func (v *ValidationResult) MergeWithFormat(format string, other ValidationResult) {
	if v.ValidationError == "" && other.ValidationError != "" {
		v.ValidationError = fmt.Sprintf(format, other.ValidationError)
	}
	for _, note := range other.ValidationNotes {
		v.ValidationNotes = append(v.ValidationNotes, fmt.Sprintf(format, note))
	}
}

