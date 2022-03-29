package fflag

// Common flags that apply to both the server and the agent
const (
	// FlagForcedRotation controls whether or not the new APIs and
	// extensions related to forced rotation and revocation are
	// enabled or not. See #1934 for more information.
	FlagForcedRotation Flag = "forced_rotation"
)

var (
	commonFlagMap = map[Flag]bool{
		FlagForcedRotation: false,
	}
)
