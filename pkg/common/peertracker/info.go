package peertracker

const (
	authType = "spire-attestation"
)

type AuthInfo struct {
	Caller  CallerInfo
	Watcher Watcher
}

// AuthType returns the authentication type and allows us to
// conform to the gRPC AuthInfo interface
func (AuthInfo) AuthType() string {
	return authType
}
