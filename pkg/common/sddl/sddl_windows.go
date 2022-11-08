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

	// PubliclyReadableFile describes a security descriptor using
	// the security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to files that need to
	// be publicly readable but writable only by the owner of the file.
	// The security descriptor grants full access to the creator owner
	// and read access to everyone.
	PubliclyReadableFile = "D:P(A;;FA;;;OW)(A;;FR;;;WD)"

	// PrivateListener describes a security descriptor using the
	// security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to named pipes
	// listeners that only need to be accessed locally by the owner
	// of the service, granting read, write and execute permissions
	// to the creator owner only. Access to the Network logon user
	// group is denied.
	// E.g.: SPIRE Server APIs, Admin APIs.
	PrivateListener = "D:P(A;;GRGWGX;;;OW)(D;;GA;;;NU)"

	// PublicListener describes a security descriptor using the
	// security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to named pipes
	// listeners that need to be publicly accessed locally, granting read,
	// write and execute permissions to everyone. Access to the
	// Network logon user group is denied.
	// E.g.: SPIFFE Workload API.
	PublicListener = "D:P(A;;GRGWGX;;;WD)(D;;GA;;;NU)"
)
