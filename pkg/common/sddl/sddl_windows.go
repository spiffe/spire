//go:build windows
// +build windows

package sddl

const (
	// PrivateFile describes a security descriptor using the security
	// descriptor definition language (SDDL) that is meant to be used
	// to define the access control to files that only need to be
	// accessed by the owner of the file, granting full access
	// to the creator owner only.
	PrivateFile = "D:P(A;;FA;;;OW)"

	// PrivateListener describes a security descriptor using the
	// security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to named pipes
	// listeners that only need to be accessed locally by the owner
	// of the service, granting read, write and execute permissions
	// to the creator owner only.
	// E.g.: SPIRE Server APIs, Admin APIs.
	PrivateListener = "D:P(A;;GRGWGX;;;OW)"

	// PublicListener describes a security descriptor using the
	// security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to named pipes
	// listeners that need to be publicly accessed, granting read,
	// write and execute permissions to everyone.
	// E.g.: SPIFFE Workload API.
	PublicListener = "D:P(A;;GRGWGX;;;WD)"
)
