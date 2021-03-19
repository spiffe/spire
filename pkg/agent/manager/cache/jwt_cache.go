package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sort"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
)

type JWTSVIDCache struct {
	mu    sync.Mutex
	svids map[string]*client.JWTSVID
}

func NewJWTSVIDCache() *JWTSVIDCache {
	return &JWTSVIDCache{
		svids: make(map[string]*client.JWTSVID),
	}
}

func (c *JWTSVIDCache) GetJWTSVID(spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, bool) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()
	svid, ok := c.svids[key]
	return svid, ok
}

func (c *JWTSVIDCache) SetJWTSVID(spiffeID spiffeid.ID, audience []string, svid *client.JWTSVID) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.svids[key] = svid
}

func jwtSVIDKey(spiffeID spiffeid.ID, audience []string) string {
	h := sha256.New()

	// duplicate and sort the audience slice
	audience = append([]string(nil), audience...)
	sort.Strings(audience)

	_, _ = io.WriteString(h, spiffeID.String())
	for _, a := range audience {
		_, _ = io.WriteString(h, a)
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
