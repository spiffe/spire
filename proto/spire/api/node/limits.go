package node

const (
	// Max burst values for ratelimiting
	// Requests containing more than this number of
	// operations will always be rejected
	CSRLimit        int = 500
	JSRLimit        int = 500
	PushJWTKeyLimit int = 500
)
