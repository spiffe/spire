package cache

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent"
)

type JWTSVIDCache struct {
	log     logrus.FieldLogger
	metrics telemetry.Metrics
	mu      sync.RWMutex

	svids   map[string]*list.Element
	lruList *list.List

	// svidCacheMaxSize is a hard limit of max number of SVIDs that would be stored in cache
	svidCacheMaxSize int
}

type jwtSvidElement struct {
	key  string
	svid *client.JWTSVID
}

func (c *JWTSVIDCache) CountJWTSVIDs() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.svids)
}

func NewJWTSVIDCache(log logrus.FieldLogger, metrics telemetry.Metrics, svidCacheMaxSize int) *JWTSVIDCache {
	if svidCacheMaxSize <= 0 {
		svidCacheMaxSize = DefaultSVIDCacheMaxSize
	}
	return &JWTSVIDCache{
		metrics:          metrics,
		log:              log,
		svids:            make(map[string]*list.Element),
		lruList:          list.New(),
		svidCacheMaxSize: svidCacheMaxSize,
	}
}

func (c *JWTSVIDCache) GetJWTSVID(spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, bool) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()

	svidElement, ok := c.svids[key]
	if !ok {
		return nil, ok
	}
	c.lruList.MoveToFront(svidElement)

	return svidElement.Value.(jwtSvidElement).svid, ok
}

func (c *JWTSVIDCache) SetJWTSVID(spiffeID spiffeid.ID, audience []string, svid *client.JWTSVID) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.svids) >= c.svidCacheMaxSize {
		element := c.lruList.Back()
		jwtSvidWithHash := element.Value.(jwtSvidElement)
		delete(c.svids, jwtSvidWithHash.key)
		c.lruList.Remove(element)
	}

	svidElement, ok := c.svids[key]
	if ok {
		svidElement.Value = jwtSvidElement{
			key:  key,
			svid: svid,
		}
		c.lruList.MoveToFront(svidElement)
	} else {
		svidElement = c.lruList.PushFront(jwtSvidElement{
			key:  key,
			svid: svid,
		})
		c.svids[key] = svidElement
	}
}

func (c *JWTSVIDCache) TaintJWTSVIDs(ctx context.Context, taintedJWTAuthorities map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	counter := telemetry.StartCall(c.metrics, telemetry.CacheManager, agent.CacheTypeWorkload, telemetry.ProcessTaintedJWTSVIDs)
	defer counter.Done(nil)

	removedKeyIDs := make(map[string]int)
	totalCount := 0
	for key, element := range c.svids {
		jwtSvidElement := element.Value.(jwtSvidElement)
		keyID, err := getKeyIDFromSVIDToken(jwtSvidElement.svid.Token)
		if err != nil {
			c.log.WithError(err).Error("Could not get key ID from cached JWT-SVID")
			continue
		}

		if _, tainted := taintedJWTAuthorities[keyID]; tainted {
			delete(c.svids, key)
			c.lruList.Remove(element)

			removedKeyIDs[keyID]++
			totalCount++
		}
		select {
		case <-ctx.Done():
			c.log.WithError(ctx.Err()).Warn("Context cancelled, exiting process of tainting JWT-SVIDs in cache")
			return
		default:
		}
	}
	for keyID, count := range removedKeyIDs {
		c.log.WithField(telemetry.JWTAuthorityKeyIDs, keyID).
			WithField(telemetry.TaintedJWTSVIDs, count).
			Info("JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority")
	}
	agent.AddCacheManagerTaintedJWTSVIDsSample(c.metrics, agent.CacheTypeWorkload, float32(totalCount))
}

func getKeyIDFromSVIDToken(svidToken string) (string, error) {
	token, err := jwt.ParseSigned(svidToken, jwtsvid.AllowedSignatureAlgorithms)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT-SVID: %w", err)
	}

	if len(token.Headers) != 1 {
		return "", fmt.Errorf("malformed JWT-SVID: expected a single token header; got %d", len(token.Headers))
	}

	keyID := token.Headers[0].KeyID
	if keyID == "" {
		return "", errors.New("missing key ID in token header of minted JWT-SVID")
	}

	return keyID, nil
}

func jwtSVIDKey(spiffeID spiffeid.ID, audience []string) string {
	h := sha256.New()

	// Form the cache key as the SHA-256 hash of the SPIFFE ID and all the audiences.
	// In order to avoid ambiguities, we will write a nul byte to the hash function after each data
	// item.

	// duplicate and sort the audience slice
	audience = append([]string(nil), audience...)
	sort.Strings(audience)

	_, _ = io.WriteString(h, spiffeID.String())
	h.Write([]byte{0})
	for _, a := range audience {
		_, _ = io.WriteString(h, a)
		h.Write([]byte{0})
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
