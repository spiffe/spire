package testdata

import _ "embed"

var (
	//go:embed entries_federates_with.json
	EntriesFederatesWith []byte

	//go:embed entries.json
	Entries []byte

	//go:embed invalid_registration_entries.json
	InvalidRegistrationEntries []byte

	//go:embed valid_registration_entries.json
	ValidRegistrationEntries []byte
)
