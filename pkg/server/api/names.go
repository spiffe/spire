package api

type Names struct {
	// Service is the service name with the common prefix removed (e.g.,
	// svid.v1.SVID).
	Service string

	// Method is the method name (e.g. MintX509SVID)
	Method string
}
