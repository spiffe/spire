package authoritycommon

import (
	"time"

	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

func PrettyPrintJWTAuthorityState(env *commoncli.Env, authorityState *localauthorityv1.AuthorityState) {
	prettyPrintAuthorityState(env, authorityState, false)
}

func PrettyPrintX509AuthorityState(env *commoncli.Env, authorityState *localauthorityv1.AuthorityState) {
	prettyPrintAuthorityState(env, authorityState, true)
}

func prettyPrintAuthorityState(env *commoncli.Env, authorityState *localauthorityv1.AuthorityState, includeUpstreamAuthority bool) {
	env.Printf("  Authority ID: %s\n", authorityState.AuthorityId)
	env.Printf("  Expires at: %s\n", time.Unix(authorityState.ExpiresAt, 0).UTC())
	if !includeUpstreamAuthority {
		return
	}

	if authorityState.UpstreamAuthoritySubjectKeyId != "" {
		env.Printf("  Upstream authority Subject Key ID: %s\n", authorityState.UpstreamAuthoritySubjectKeyId)
		return
	}

	env.Println("  Upstream authority ID: No upstream authority")
}
