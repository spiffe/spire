package manager

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/svid"
	"github.com/spiffe/spire/pkg/agent/trustbundlesources"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	testclock "github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type jwtSigningCall struct {
	ctx      context.Context
	entryID  string
	audience []string
	hit      bool
	result   chan jwtSigningResult
}

type jwtSigningResult struct {
	svid *client.JWTSVID
	id   spiffeid.ID
	err  error
}

type jwtControlledClient struct {
	client.Client
	mu         sync.Mutex
	calls      []*jwtSigningCall
	update     *client.Update
	fetchErr   error
	fetchCount int
}

func (c *jwtControlledClient) PostStatus(context.Context, string) error { return nil }
func (c *jwtControlledClient) Release()                                 {}
func (c *jwtControlledClient) NewX509SVIDs(context.Context, map[string][]byte) (map[string]*client.X509SVID, error) {
	return map[string]*client.X509SVID{}, nil
}
func (c *jwtControlledClient) FetchUpdates(context.Context) (*client.Update, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetchCount++
	if c.fetchErr != nil {
		return nil, c.fetchErr
	}
	u := &client.Update{Entries: map[string]*common.RegistrationEntry{}, Bundles: map[string]*common.Bundle{}}
	for k, v := range c.update.Entries {
		u.Entries[k] = proto.Clone(v).(*common.RegistrationEntry)
	}
	for k, v := range c.update.Bundles {
		u.Bundles[k] = proto.Clone(v).(*common.Bundle)
	}
	return u, nil
}
func (c *jwtControlledClient) SyncUpdates(ctx context.Context, entries map[string]*common.RegistrationEntry, bundles map[string]*common.Bundle) (client.SyncStats, error) {
	u, err := c.FetchUpdates(ctx)
	if err != nil {
		return client.SyncStats{}, err
	}
	clear(entries)
	clear(bundles)
	maps.Copy(entries, u.Entries)
	maps.Copy(bundles, u.Bundles)
	return client.SyncStats{}, nil
}

type jwtMemoryStorage struct{ storage.Storage }

func (jwtMemoryStorage) StoreSVID([]*x509.Certificate, bool) error { return nil }
func (jwtMemoryStorage) StoreBundle([]*x509.Certificate) error     { return nil }

type jwtIdleRotator struct{ svid.Rotator }

func (jwtIdleRotator) Run(ctx context.Context) error { <-ctx.Done(); return nil }

func (c *jwtControlledClient) NewJWTSVID(ctx context.Context, id string, audience []string, hit bool) (*client.JWTSVID, spiffeid.ID, error) {
	call := &jwtSigningCall{ctx: ctx, entryID: id, audience: audience, hit: hit, result: make(chan jwtSigningResult, 1)}
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
	r := <-call.result
	return r.svid, r.id, r.err
}

func (c *jwtControlledClient) snapshot() []*jwtSigningCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*jwtSigningCall(nil), c.calls...)
}

type jwtFixture struct {
	m       *manager
	client  *jwtControlledClient
	clock   *testclock.Mock
	metrics *fakemetrics.FakeMetrics
}

func newJWTFixture(t *testing.T, enabled bool, capacity int, configure ...func(*Config)) *jwtFixture {
	log, _ := test.NewNullLogger()
	clk := testclock.NewMock(t)
	metrics := fakemetrics.New()
	cfg := &Config{Log: log, Metrics: metrics, Catalog: fakeagentcatalog.New(), TrustDomain: trustDomain,
		Clk: clk, JWTSVIDCacheMaxSize: capacity, RotationStrategy: rotationutil.NewRotationStrategy(0)}
	cfg.Storage = jwtMemoryStorage{}
	cfg.WorkloadKeyType = workloadkey.ECP256
	cfg.SVIDStoreCache = storecache.New(&storecache.Config{Log: log, TrustDomain: trustDomain, Metrics: metrics})
	cfg.TrustBundleSources = trustbundlesources.New(&trustbundlesources.Config{TrustDomain: trustDomain.Name()}, log)
	f := reflect.ValueOf(cfg).Elem().FieldByName("JWTSVIDRequestCoalescing")
	require.True(t, f.IsValid(), "manager configuration must expose JWTSVIDRequestCoalescing")
	require.Equal(t, reflect.Bool, f.Kind())
	f.SetBool(enabled)
	for _, configureConfig := range configure {
		configureConfig(cfg)
	}
	m := New(cfg).(*manager)
	c := &jwtControlledClient{}
	m.client = c
	m.svid = jwtIdleRotator{m.svid}
	t.Cleanup(func() {
		for _, call := range c.snapshot() {
			select {
			case call.result <- jwtSigningResult{err: errors.New("cleanup")}:
			default:
			}
		}
	})
	return &jwtFixture{m: m, client: c, clock: clk, metrics: metrics}
}

func jwtEntry(id string, revision int64) *common.RegistrationEntry {
	return &common.RegistrationEntry{EntryId: id, RevisionNumber: revision, SpiffeId: "spiffe://example.org/workload"}
}

func jwtValue(now time.Time, kid, value string) *client.JWTSVID {
	enc := base64.RawURLEncoding.EncodeToString
	// The client boundary supplies already-validated signing results.
	token := enc(fmt.Appendf(nil, `{"alg":"ES256","kid":%q}`, kid)) + "." + enc(fmt.Appendf(nil, `{"value":%q}`, value)) + "." + enc(make([]byte, 64))
	return &client.JWTSVID{Token: token, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func jwtStart(ctx context.Context, f *jwtFixture, entry *common.RegistrationEntry, audience []string) <-chan jwtSigningResult {
	ch := make(chan jwtSigningResult, 1)
	go func() {
		svid, err := f.m.FetchJWTSVID(ctx, entry, audience)
		ch <- jwtSigningResult{svid: svid, err: err}
	}()
	synctest.Wait()
	return ch
}

func jwtComplete(call *jwtSigningCall, svid *client.JWTSVID, err error) {
	call.result <- jwtSigningResult{svid: svid, id: spiffeid.RequireFromString("spiffe://example.org/workload"), err: err}
	synctest.Wait()
}

func jwtTake(t *testing.T, ch <-chan jwtSigningResult) jwtSigningResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	default:
		t.Fatal("caller did not complete")
		return jwtSigningResult{}
	}
}

func jwtAudienceSet(audience []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, value := range audience {
		set[value] = struct{}{}
	}
	return set
}

func jwtRequireCacheSize(t *testing.T, f *jwtFixture, want int) {
	t.Helper()
	found := false
	last := float64(-1)
	for _, item := range f.metrics.AllMetrics() {
		if reflect.DeepEqual(item.Key, []string{"jwt_svid_cache_size"}) && item.Type == fakemetrics.SetGaugeType {
			last = item.Val
			found = true
		}
	}
	require.True(t, found, "JWT cache size metric must include coordinated entries")
	require.Equal(t, float64(want), last)
}

func TestJWTRequestCoalescingEquivalentRequests(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second []string
	}{
		{"reordered_duplicates", []string{"b", "a", "a"}, []string{"a", "b"}},
		{"empty_set", nil, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newJWTFixture(t, true, 10)
				entry := jwtEntry("one", 1)
				entry.JwtSvidTtl = 600
				entry.Selectors = []*common.Selector{{Type: "unix", Value: "uid:1000"}}
				originalEntry := proto.Clone(entry).(*common.RegistrationEntry)
				audience := slices.Clone(tc.first)
				first := jwtStart(context.Background(), f, entry, audience)
				second := jwtStart(context.Background(), f, jwtEntry("one", 1), tc.second)
				calls := f.client.snapshot()
				require.Len(t, calls, 1)
				require.False(t, calls[0].hit)
				require.Equal(t, "one", calls[0].entryID)
				require.Equal(t, jwtAudienceSet(tc.first), jwtAudienceSet(calls[0].audience))
				require.Equal(t, tc.first, audience)
				require.True(t, proto.Equal(originalEntry, entry), "signing must preserve the entire registration entry")
				if len(audience) > 0 {
					audience[0] = "changed"
				}
				entry.EntryId = "changed"
				originalEntry.EntryId = "changed"
				require.NotContains(t, calls[0].audience, "changed")
				value := jwtValue(f.clock.Now(), "clean", "shared")
				jwtComplete(calls[0], value, nil)
				require.True(t, proto.Equal(originalEntry, entry), "completion must preserve the caller's entry")
				a, b := jwtTake(t, first), jwtTake(t, second)
				require.NoError(t, a.err)
				require.NoError(t, b.err)
				require.Equal(t, value, a.svid)
				require.Equal(t, value, b.svid)
				a.svid.Token = "changed"
				require.Equal(t, value.Token, b.svid.Token)
				cachedEntry := proto.Clone(originalEntry).(*common.RegistrationEntry)
				cachedEntry.EntryId = "one"
				originalCachedEntry := proto.Clone(cachedEntry)
				cachedAudience := slices.Clone(tc.first)
				cached, err := f.m.FetchJWTSVID(context.Background(), cachedEntry, cachedAudience)
				require.NoError(t, err)
				require.True(t, proto.Equal(originalCachedEntry, cachedEntry), "cache hits must preserve the caller's entry")
				require.Equal(t, tc.first, cachedAudience)
				require.Equal(t, value, cached)
				cached.Token = "changed again"
				cached, err = f.m.FetchJWTSVID(context.Background(), jwtEntry("one", 1), tc.second)
				require.NoError(t, err)
				require.Equal(t, value, cached)
				require.Len(t, f.client.snapshot(), 1)
			})
		})
	}
}

func TestJWTRequestCoalescingIdentityIsolation(t *testing.T) {
	for _, axis := range []string{"entry", "revision", "spiffe", "audience", "separator", "comma", "space", "instance"} {
		t.Run(axis, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newJWTFixture(t, true, 10)
				other := f
				a, b := jwtEntry("one", 1), jwtEntry("one", 1)
				aa, bb := []string{"a", "b"}, []string{"a", "b"}
				switch axis {
				case "entry":
					b.EntryId = "two"
				case "revision":
					b.RevisionNumber = 2
				case "spiffe":
					b.SpiffeId = "spiffe://example.org/other"
				case "audience":
					bb = []string{"a", "c"}
				case "separator":
					aa = []string{"a\x00b"}
					bb = []string{"a", "b"}
				case "comma":
					aa = []string{"a,b"}
				case "space":
					aa = []string{"a b"}
				case "instance":
					other = newJWTFixture(t, true, 10)
				}
				one := jwtStart(context.Background(), f, a, aa)
				two := jwtStart(context.Background(), other, b, bb)
				ca, cb := f.client.snapshot(), other.client.snapshot()
				if axis == "instance" {
					require.Len(t, ca, 1)
					require.Len(t, cb, 1)
				} else {
					require.Len(t, ca, 2)
				}
				va, vb := jwtValue(f.clock.Now(), "clean", "one"), jwtValue(f.clock.Now(), "clean", "two")
				jwtComplete(ca[0], va, nil)
				callB := cb[len(cb)-1]
				require.Equal(t, a.EntryId, ca[0].entryID)
				require.Equal(t, b.EntryId, callB.entryID)
				require.Equal(t, jwtAudienceSet(aa), jwtAudienceSet(ca[0].audience))
				require.Equal(t, jwtAudienceSet(bb), jwtAudienceSet(callB.audience))
				callB.result <- jwtSigningResult{svid: vb, id: spiffeid.RequireFromString(b.SpiffeId)}
				synctest.Wait()
				require.Equal(t, va, jwtTake(t, one).svid)
				require.Equal(t, vb, jwtTake(t, two).svid)
				cachedA, err := f.m.FetchJWTSVID(context.Background(), a, aa)
				require.NoError(t, err)
				require.Equal(t, va, cachedA)
				cachedB, err := other.m.FetchJWTSVID(context.Background(), b, bb)
				require.NoError(t, err)
				require.Equal(t, vb, cachedB)
			})
		})
	}
}

func TestJWTRequestCoalescingCallerDeparture(t *testing.T) {
	for _, departing := range []string{"initiator", "follower", "deadline"} {
		t.Run(departing, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newJWTFixture(t, true, 10)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if departing == "deadline" {
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					defer cancel()
				}
				firstCtx, secondCtx := ctx, context.Background()
				if departing == "follower" {
					firstCtx, secondCtx = secondCtx, firstCtx
				}
				one := jwtStart(firstCtx, f, jwtEntry("one", 1), nil)
				two := jwtStart(secondCtx, f, jwtEntry("one", 1), nil)
				require.Len(t, f.client.snapshot(), 1)
				if departing == "deadline" {
					time.Sleep(time.Second)
				} else {
					cancel()
				}
				synctest.Wait()
				gone, remaining := one, two
				if departing == "follower" {
					gone, remaining = two, one
				}
				err := context.Canceled
				if departing == "deadline" {
					err = context.DeadlineExceeded
				}
				require.ErrorIs(t, jwtTake(t, gone).err, err)
				call := f.client.snapshot()[0]
				require.NoError(t, call.ctx.Err())
				value := jwtValue(f.clock.Now(), "clean", "live")
				jwtComplete(call, value, nil)
				r := jwtTake(t, remaining)
				require.NoError(t, r.err)
				require.Equal(t, value, r.svid)
			})
		})
	}
}

func TestJWTRequestCoalescingAbandonedReplacement(t *testing.T) {
	for _, lateFailure := range []bool{false, true} {
		for _, completesLast := range []bool{false, true} {
			t.Run(fmt.Sprintf("failure=%t/afterReplacement=%t", lateFailure, completesLast), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newJWTFixture(t, true, 10)
					entry := jwtEntry("one", 1)
					ctx, cancel := context.WithCancel(context.Background())
					ctx2, cancel2 := context.WithCancel(context.Background())
					defer cancel()
					defer cancel2()
					old := jwtStart(ctx, f, entry, nil)
					follower := jwtStart(ctx2, f, entry, nil)
					require.Len(t, f.client.snapshot(), 1)
					call := f.client.snapshot()[0]
					cancel()
					synctest.Wait()
					require.ErrorIs(t, jwtTake(t, old).err, context.Canceled)
					require.NoError(t, call.ctx.Err())
					cancel2()
					synctest.Wait()
					require.ErrorIs(t, jwtTake(t, follower).err, context.Canceled)
					require.ErrorIs(t, call.ctx.Err(), context.Canceled)
					newCall := jwtStart(context.Background(), f, entry, nil)
					require.Len(t, f.client.snapshot(), 2)
					lateErr := error(nil)
					if lateFailure {
						lateErr = errors.New("late failure")
					}
					if !completesLast {
						jwtComplete(call, jwtValue(f.clock.Now(), "clean", "old"), lateErr)
						require.Zero(t, f.m.CountJWTSVIDs())
					}
					joined := jwtStart(context.Background(), f, entry, nil)
					require.Len(t, f.client.snapshot(), 2)
					value := jwtValue(f.clock.Now(), "clean", "replacement")
					jwtComplete(f.client.snapshot()[1], value, nil)
					for _, ch := range []<-chan jwtSigningResult{newCall, joined} {
						r := jwtTake(t, ch)
						require.NoError(t, r.err)
						require.Equal(t, value, r.svid)
					}
					if completesLast {
						jwtComplete(call, jwtValue(f.clock.Now(), "clean", "old"), lateErr)
					}
					cached, err := f.m.FetchJWTSVID(context.Background(), entry, nil)
					require.NoError(t, err)
					require.Equal(t, value, cached)
				})
			})
		}
	}
}

func TestJWTRequestCoalescingCanceledPreflight(t *testing.T) {
	for _, cached := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("cached=%t/expired=%t", cached, expired), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newJWTFixture(t, true, 10)
					entry := jwtEntry("one", 1)
					if cached {
						ch := jwtStart(context.Background(), f, entry, nil)
						jwtComplete(f.client.snapshot()[0], jwtValue(f.clock.Now(), "clean", "cached"), nil)
						require.NoError(t, jwtTake(t, ch).err)
					}
					count := len(f.client.snapshot())
					originalEntry := proto.Clone(entry)
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					want := context.Canceled
					if expired {
						ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
						defer cancel()
						want = context.DeadlineExceeded
					}
					r := jwtTake(t, jwtStart(ctx, f, entry, nil))
					require.ErrorIs(t, r.err, want)
					require.Nil(t, r.svid)
					require.Len(t, f.client.snapshot(), count)
					require.True(t, proto.Equal(originalEntry, entry), "cancellation must preserve the caller's entry")
				})
			})
		}
	}
}

func TestJWTRequestCoalescingJTIAndDisabled(t *testing.T) {
	t.Run("disabled_audience_multiplicity", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newJWTFixture(t, false, 10)
			entry := jwtEntry("one", 1)
			first := jwtStart(context.Background(), f, entry, []string{"a", "a"})
			calls := f.client.snapshot()
			require.Len(t, calls, 1)
			jwtComplete(calls[0], jwtValue(f.clock.Now(), "clean", "duplicates"), nil)
			require.NoError(t, jwtTake(t, first).err)

			second := jwtStart(context.Background(), f, entry, []string{"a"})
			calls = f.client.snapshot()
			if len(calls) == 2 {
				jwtComplete(calls[1], jwtValue(f.clock.Now(), "clean", "single"), nil)
			}
			require.NoError(t, jwtTake(t, second).err)
			require.Len(t, calls, 2, "disabled mode must retain legacy audience-sensitive cache reuse")
		})
	})
	t.Run("jti_after_authorization_snapshot", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newJWTFixture(t, true, 10)
			f.client.update = &client.Update{Entries: map[string]*common.RegistrationEntry{}, Bundles: map[string]*common.Bundle{}}
			require.NoError(t, f.m.Initialize(context.Background()))
			entry := jwtEntry("one", 1)
			entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{JwtSvidIncludeJti: true}
			one := jwtStart(context.Background(), f, entry, []string{"fresh"})
			two := jwtStart(context.Background(), f, entry, []string{"fresh"})
			calls := f.client.snapshot()
			require.Len(t, calls, 2, "JTI requests must retain independent signing outside coordination")
			for i, result := range []<-chan jwtSigningResult{one, two} {
				require.False(t, calls[i].hit)
				value := jwtValue(f.clock.Now(), "clean", fmt.Sprint(i))
				jwtComplete(calls[i], value, nil)
				got := jwtTake(t, result)
				require.NoError(t, got.err)
				require.Equal(t, value, got.svid)
			}
			require.Zero(t, f.m.CountJWTSVIDs(), "JTI signing must remain uncached")
		})
	})
	for _, mode := range []string{"jti", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newJWTFixture(t, mode != "disabled", 10)
				entry := jwtEntry("one", 1)
				var seedValue *client.JWTSVID
				if mode == "jti" {
					seedValue = jwtValue(f.clock.Now(), "clean", "seed")
					seed := jwtStart(context.Background(), f, entry, []string{"fresh"})
					jwtComplete(f.client.snapshot()[0], seedValue, nil)
					require.NoError(t, jwtTake(t, seed).err)
					entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{JwtSvidIncludeJti: true}
				}
				start := len(f.client.snapshot())
				one := jwtStart(context.Background(), f, entry, []string{"fresh"})
				two := jwtStart(context.Background(), f, entry, []string{"fresh"})
				calls := f.client.snapshot()
				require.Len(t, calls, start+2)
				for i, ch := range []<-chan jwtSigningResult{one, two} {
					require.False(t, calls[start+i].hit)
					require.Equal(t, entry.EntryId, calls[start+i].entryID)
					require.Equal(t, jwtAudienceSet([]string{"fresh"}), jwtAudienceSet(calls[start+i].audience))
					v := jwtValue(f.clock.Now(), "clean", fmt.Sprint(i))
					jwtComplete(calls[start+i], v, nil)
					require.Equal(t, v, jwtTake(t, ch).svid)
				}
				if mode == "jti" {
					require.Equal(t, 1, f.m.CountJWTSVIDs())
					regularEntry := proto.Clone(entry).(*common.RegistrationEntry)
					regularEntry.AdditionalAttributes = nil
					cached := jwtTake(t, jwtStart(context.Background(), f, regularEntry, []string{"fresh"}))
					require.NoError(t, cached.err)
					require.Equal(t, seedValue, cached.svid, "JTI signing must not overwrite a shared token")
					require.Len(t, f.client.snapshot(), start+2)
					next := jwtStart(context.Background(), f, entry, []string{"fresh"})
					require.Len(t, f.client.snapshot(), start+3)
					jwtComplete(f.client.snapshot()[start+2], nil, errors.New("unavailable"))
					require.Error(t, jwtTake(t, next).err)
				}
			})
		})
	}
}

func TestJWTRequestCoalescingFallbackAtCompletion(t *testing.T) {
	for _, state := range []string{"valid", "expired", "canceled"} {
		t.Run(state, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newJWTFixture(t, true, 10)
				entry := jwtEntry("one", 1)
				seed := jwtStart(context.Background(), f, entry, nil)
				value := jwtValue(f.clock.Now(), "clean", "cached")
				jwtComplete(f.client.snapshot()[0], value, nil)
				require.NoError(t, jwtTake(t, seed).err)
				f.clock.Add(50 * time.Minute)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				first := jwtStart(ctx, f, entry, nil)
				second := jwtStart(context.Background(), f, entry, nil)
				require.Len(t, f.client.snapshot(), 2)
				call := f.client.snapshot()[1]
				require.True(t, call.hit)
				if state == "expired" {
					f.clock.Add(10 * time.Minute)
				}
				if state == "canceled" {
					cancel()
					synctest.Wait()
				}
				jwtComplete(call, nil, errors.New("signing failed"))
				a, b := jwtTake(t, first), jwtTake(t, second)
				if state == "expired" {
					require.Error(t, a.err)
					require.Error(t, b.err)
					require.Nil(t, a.svid)
					require.Nil(t, b.svid)
				} else {
					require.NoError(t, b.err)
					require.Equal(t, value, b.svid)
					if state == "canceled" {
						require.ErrorIs(t, a.err, context.Canceled)
					} else {
						require.NoError(t, a.err)
						require.Equal(t, value, a.svid)
					}
				}
				if state == "valid" {
					a.svid.Token = "changed-first-fallback"
					require.Equal(t, value, b.svid, "fallback results must be independent")
					b.svid.Token = "changed-second-fallback"
				}
				retry := jwtStart(context.Background(), f, entry, nil)
				require.Len(t, f.client.snapshot(), 3)
				lastCall := 2
				if state == "valid" {
					jwtComplete(f.client.snapshot()[lastCall], nil, errors.New("signing failed again"))
					fallback := jwtTake(t, retry)
					require.NoError(t, fallback.err)
					require.Equal(t, value, fallback.svid, "returned fallback mutations must not affect cache")
					retry = jwtStart(context.Background(), f, entry, nil)
					require.Len(t, f.client.snapshot(), 4)
					lastCall++
				}
				fresh := jwtValue(f.clock.Now(), "clean", "fresh")
				jwtComplete(f.client.snapshot()[lastCall], fresh, nil)
				r := jwtTake(t, retry)
				require.NoError(t, r.err)
				require.Equal(t, fresh, r.svid)
			})
		})
	}
}

func TestJWTRequestCoalescingLRUAndMetric(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newJWTFixture(t, true, 2)
		for i, id := range []string{"a", "b"} {
			ch := jwtStart(context.Background(), f, jwtEntry(id, 1), nil)
			calls := f.client.snapshot()
			jwtComplete(calls[len(calls)-1], jwtValue(f.clock.Now(), "clean", id), nil)
			require.NoError(t, jwtTake(t, ch).err)
			jwtRequireCacheSize(t, f, i+1)
		}
		require.Equal(t, 2, f.m.CountJWTSVIDs())
		f.clock.Add(50 * time.Minute)
		refresh := jwtStart(context.Background(), f, jwtEntry("a", 1), nil)
		jwtComplete(f.client.snapshot()[2], jwtValue(f.clock.Now(), "clean", "new-a"), nil)
		require.NoError(t, jwtTake(t, refresh).err)
		require.Equal(t, 2, f.m.CountJWTSVIDs(), "refreshing at capacity must preserve another identity")
		b := jwtStart(context.Background(), f, jwtEntry("b", 1), nil)
		require.True(t, f.client.snapshot()[3].hit)
		jwtComplete(f.client.snapshot()[3], jwtValue(f.clock.Now(), "clean", "new-b"), nil)
		require.NoError(t, jwtTake(t, b).err)
		_, err := f.m.FetchJWTSVID(context.Background(), jwtEntry("a", 1), nil)
		require.NoError(t, err)
		c := jwtStart(context.Background(), f, jwtEntry("c", 1), nil)
		jwtComplete(f.client.snapshot()[4], jwtValue(f.clock.Now(), "clean", "c"), nil)
		require.NoError(t, jwtTake(t, c).err)
		_, err = f.m.FetchJWTSVID(context.Background(), jwtEntry("a", 1), nil)
		require.NoError(t, err)
		require.Len(t, f.client.snapshot(), 5)
		b = jwtStart(context.Background(), f, jwtEntry("b", 1), nil)
		require.Len(t, f.client.snapshot(), 6)
		require.False(t, f.client.snapshot()[5].hit)
		jwtComplete(f.client.snapshot()[5], jwtValue(f.clock.Now(), "clean", "b-again"), nil)
		require.NoError(t, jwtTake(t, b).err)
		require.Equal(t, 2, f.m.CountJWTSVIDs())
		jwtRequireCacheSize(t, f, 2)
		f.clock.Add(24 * time.Hour)
		synctest.Wait()
		require.Len(t, f.client.snapshot(), 6, "idle time must not start signing")
	})
}

func TestJWTRequestCoalescingTaintedAuthorities(t *testing.T) {
	t.Run("clean_fallback_after_tainted_refresh", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newJWTFixture(t, true, 10)
			entry := jwtEntry("one", 1)
			entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
			key, err := x509.MarshalPKIXPublicKey(serverKey.Public())
			require.NoError(t, err)
			bundle := &common.Bundle{TrustDomainId: trustDomain.IDString(),
				JwtSigningKeys: []*common.PublicKey{{Kid: "bad", PkixBytes: key}}}
			f.client.update = &client.Update{Entries: map[string]*common.RegistrationEntry{entry.EntryId: entry},
				Bundles: map[string]*common.Bundle{trustDomain.IDString(): bundle}}
			require.NoError(t, f.m.Initialize(context.Background()))

			cached := jwtValue(f.clock.Now(), "clean", "cached")
			seed := jwtStart(context.Background(), f, entry, nil)
			jwtComplete(f.client.snapshot()[0], cached, nil)
			require.NoError(t, jwtTake(t, seed).err)
			f.clock.Add(50 * time.Minute)
			bundle.JwtSigningKeys[0].TaintedKey = true
			require.NoError(t, f.m.Initialize(context.Background()))
			require.Equal(t, 1, f.m.CountJWTSVIDs(), "tainting bad must preserve a clean cached token")

			refresh := jwtStart(context.Background(), f, entry, nil)
			calls := f.client.snapshot()
			require.Len(t, calls, 2)
			require.True(t, calls[1].hit)
			jwtComplete(calls[1], jwtValue(f.clock.Now(), "bad", "rejected"), nil)
			result := jwtTake(t, refresh)
			require.NoError(t, result.err)
			require.Equal(t, cached, result.svid, "rejected tainted signing may use the still-valid clean fallback")
			require.Equal(t, 1, f.m.CountJWTSVIDs())
		})
	})
	t.Run("signing_completion", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newJWTFixture(t, true, 10)
			entries := map[string]*common.RegistrationEntry{
				"one":     jwtEntry("one", 1),
				"two":     jwtEntry("two", 2),
				"healthy": jwtEntry("healthy", 1),
				"pending": jwtEntry("pending", 1),
			}
			for _, entry := range entries {
				entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
			}
			key, err := x509.MarshalPKIXPublicKey(serverKey.Public())
			require.NoError(t, err)
			bundle := &common.Bundle{TrustDomainId: trustDomain.IDString(),
				JwtSigningKeys: []*common.PublicKey{{Kid: "bad", PkixBytes: key}}}
			f.client.update = &client.Update{Entries: entries,
				Bundles: map[string]*common.Bundle{trustDomain.IDString(): bundle}}
			require.NoError(t, f.m.Initialize(context.Background()))
			for _, id := range []string{"one", "two"} {
				ch := jwtStart(context.Background(), f, entries[id], nil)
				calls := f.client.snapshot()
				jwtComplete(calls[len(calls)-1], jwtValue(f.clock.Now(), "bad", id), nil)
				require.NoError(t, jwtTake(t, ch).err)
			}
			healthyEntry := jwtEntry("healthy", 1)
			healthyToken := jwtValue(f.clock.Now(), "clean", "healthy")
			healthy := jwtStart(context.Background(), f, healthyEntry, nil)
			jwtComplete(f.client.snapshot()[2], healthyToken, nil)
			require.NoError(t, jwtTake(t, healthy).err)
			entry := jwtEntry("pending", 1)
			pending := jwtStart(context.Background(), f, entry, nil)
			bundle.JwtSigningKeys[0].TaintedKey = true
			require.NoError(t, f.m.Initialize(context.Background()))
			require.Equal(t, 1, f.m.CountJWTSVIDs())
			cachedHealthy := jwtTake(t, jwtStart(context.Background(), f, healthyEntry, nil))
			require.NoError(t, cachedHealthy.err)
			require.Equal(t, healthyToken, cachedHealthy.svid)
			require.Len(t, f.client.snapshot(), 4, "untainted cached token should remain usable")
			jwtComplete(f.client.snapshot()[3], jwtValue(f.clock.Now(), "bad", "late"), nil)
			r := jwtTake(t, pending)
			require.Error(t, r.err)
			require.Nil(t, r.svid)
			require.Equal(t, 1, f.m.CountJWTSVIDs())
			again := jwtStart(context.Background(), f, entry, nil)
			jwtComplete(f.client.snapshot()[4], jwtValue(f.clock.Now(), "bad", "still-bad"), nil)
			require.Error(t, jwtTake(t, again).err)
			good := jwtStart(context.Background(), f, entry, nil)
			value := jwtValue(f.clock.Now(), "clean", "recovered")
			jwtComplete(f.client.snapshot()[5], value, nil)
			r = jwtTake(t, good)
			require.NoError(t, r.err)
			require.Equal(t, value, r.svid)
		})
	})
	t.Run("tainted_fallback", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newJWTFixture(t, true, 10)
			entry := jwtEntry("one", 1)
			entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
			key, err := x509.MarshalPKIXPublicKey(serverKey.Public())
			require.NoError(t, err)
			bundle := &common.Bundle{TrustDomainId: trustDomain.IDString(),
				JwtSigningKeys: []*common.PublicKey{{Kid: "bad", PkixBytes: key}}}
			f.client.update = &client.Update{Entries: map[string]*common.RegistrationEntry{entry.EntryId: entry},
				Bundles: map[string]*common.Bundle{trustDomain.IDString(): bundle}}
			require.NoError(t, f.m.Initialize(context.Background()))
			seed := jwtStart(context.Background(), f, entry, nil)
			jwtComplete(f.client.snapshot()[0], jwtValue(f.clock.Now(), "bad", "cached"), nil)
			require.NoError(t, jwtTake(t, seed).err)
			f.clock.Add(50 * time.Minute)
			pending := jwtStart(context.Background(), f, entry, nil)
			require.Len(t, f.client.snapshot(), 2)
			require.True(t, f.client.snapshot()[1].hit)
			bundle.JwtSigningKeys[0].TaintedKey = true
			require.NoError(t, f.m.Initialize(context.Background()))
			require.Zero(t, f.m.CountJWTSVIDs())
			jwtComplete(f.client.snapshot()[1], nil, errors.New("signing unavailable"))
			result := jwtTake(t, pending)
			require.Error(t, result.err, "a tainted token cannot be returned as fallback")
			require.Nil(t, result.svid)
		})
	})
}

func TestJWTRequestCoalescingAuthorizationUpdates(t *testing.T) {
	for _, change := range []string{"removed", "revision", "spiffe"} {
		for _, state := range []string{"cached", "pending"} {
			t.Run("first_snapshot/"+state+"/"+change, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newJWTFixture(t, true, 10)
					entry := jwtEntry("one", 1)
					request := jwtStart(context.Background(), f, entry, []string{"cached"})
					require.Len(t, f.client.snapshot(), 1)
					call := f.client.snapshot()[0]
					if state == "cached" {
						jwtComplete(call, jwtValue(f.clock.Now(), "clean", "before-snapshot"), nil)
						require.NoError(t, jwtTake(t, request).err)
						require.Equal(t, 1, f.m.CountJWTSVIDs())
					}
					updated := proto.Clone(entry).(*common.RegistrationEntry)
					updated.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
					entries := map[string]*common.RegistrationEntry{entry.EntryId: updated}
					switch change {
					case "removed":
						clear(entries)
					case "revision":
						updated.RevisionNumber++
					case "spiffe":
						updated.SpiffeId = "spiffe://example.org/replaced"
					}
					f.client.update = &client.Update{Entries: entries}
					require.NoError(t, f.m.Initialize(context.Background()))
					synctest.Wait()
					require.Zero(t, f.m.CountJWTSVIDs(), "first snapshot must evict invalid cached identities")
					if state == "cached" {
						jwtRequireCacheSize(t, f, 0)
					} else {
						result := jwtTake(t, request)
						require.Equal(t, codes.PermissionDenied, status.Code(result.err))
						require.Nil(t, result.svid)
						require.ErrorIs(t, call.ctx.Err(), context.Canceled)
						jwtComplete(call, jwtValue(f.clock.Now(), "clean", "invalidated"), nil)
						require.Zero(t, f.m.CountJWTSVIDs())
					}
					rejected := jwtTake(t, jwtStart(context.Background(), f, entry, []string{"cached"}))
					require.Equal(t, codes.PermissionDenied, status.Code(rejected.err))
					require.Nil(t, rejected.svid)
					require.Len(t, f.client.snapshot(), 1)
				})
			})
		}
	}

	t.Run("initial_empty_snapshot", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newJWTFixture(t, true, 10)
			f.client.update = &client.Update{Entries: map[string]*common.RegistrationEntry{}}
			require.NoError(t, f.m.Initialize(context.Background()))
			result := jwtTake(t, jwtStart(context.Background(), f, jwtEntry("absent", 1), nil))
			require.Equal(t, codes.PermissionDenied, status.Code(result.err))
			require.Nil(t, result.svid)
			require.Empty(t, f.client.snapshot())
		})
	})

	{
		for _, change := range []string{"removed", "revision", "spiffe", "failed", "empty"} {
			t.Run("sync/"+change, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newJWTFixture(t, true, 10)
					a, b := jwtEntry("one", 1), jwtEntry("two", 1)
					a.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
					b.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
					b.StoreSvid = true
					setUpdate := func(entries map[string]*common.RegistrationEntry, err error) {
						f.client.mu.Lock()
						defer f.client.mu.Unlock()
						f.client.update = &client.Update{Entries: entries}
						f.client.fetchErr = err
					}
					setUpdate(map[string]*common.RegistrationEntry{"one": a, "two": b}, nil)
					require.NoError(t, f.m.Initialize(context.Background()))
					ctx, cancel := context.WithCancel(context.Background())
					done := make(chan error, 1)
					go func() { done <- f.m.Run(ctx) }()
					synctest.Wait()
					defer func() {
						cancel()
						synctest.Wait()
						select {
						case err := <-done:
							require.NoError(t, err)
						default:
							t.Error("manager did not stop")
						}
					}()
					tick := func() {
						f.client.mu.Lock()
						before := f.client.fetchCount
						f.client.mu.Unlock()
						f.clock.Add(10 * time.Second)
						synctest.Wait()
						f.client.mu.Lock()
						after := f.client.fetchCount
						f.client.mu.Unlock()
						require.Greater(t, after, before, "authorization fetch must have run")
					}
					seed := jwtStart(context.Background(), f, a, []string{"cached"})
					cached := jwtValue(f.clock.Now(), "clean", "cached")
					jwtComplete(f.client.snapshot()[0], cached, nil)
					require.NoError(t, jwtTake(t, seed).err)
					pending := jwtStart(context.Background(), f, a, []string{"pending"})
					oldCall := f.client.snapshot()[1]
					unaffected := jwtStart(context.Background(), f, b, nil)
					stableCall := f.client.snapshot()[2]
					stableToken := jwtValue(f.clock.Now(), "clean", "stable-cache")
					stableSeed := jwtStart(context.Background(), f, b, []string{"cached"})
					jwtComplete(f.client.snapshot()[3], stableToken, nil)
					require.NoError(t, jwtTake(t, stableSeed).err)
					updated := proto.Clone(a).(*common.RegistrationEntry)
					snapshot := map[string]*common.RegistrationEntry{"one": updated, "two": b}
					switch change {
					case "empty":
						clear(snapshot)
					case "removed":
						delete(snapshot, "one")
					case "revision":
						updated.RevisionNumber++
					case "spiffe":
						updated.SpiffeId = "spiffe://example.org/changed"
					}
					fetchErr := error(nil)
					if change == "failed" {
						fetchErr = errors.New("fetch unavailable")
						snapshot = nil
					}
					setUpdate(snapshot, fetchErr)
					tick()
					if change == "empty" {
						require.Equal(t, codes.PermissionDenied, status.Code(jwtTake(t, unaffected).err))
						require.ErrorIs(t, stableCall.ctx.Err(), context.Canceled)
					} else {
						require.NoError(t, stableCall.ctx.Err(), "unrelated registration was canceled")
						stable := jwtTake(t, jwtStart(context.Background(), f, b, []string{"cached"}))
						require.NoError(t, stable.err)
						require.Equal(t, stableToken, stable.svid, "unchanged registration must retain its cached token")
						require.Len(t, f.client.snapshot(), 4)
					}
					remaining := 1
					if change == "empty" {
						remaining = 0
					}
					if change == "failed" {
						require.NoError(t, oldCall.ctx.Err())
						require.Equal(t, 2, f.m.CountJWTSVIDs())
						value, err := f.m.FetchJWTSVID(context.Background(), a, []string{"cached"})
						require.NoError(t, err)
						require.Equal(t, cached, value)
						jwtComplete(oldCall, jwtValue(f.clock.Now(), "clean", "pending"), nil)
						require.NoError(t, jwtTake(t, pending).err)
					} else {
						require.Equal(t, codes.PermissionDenied, status.Code(jwtTake(t, pending).err))
						require.ErrorIs(t, oldCall.ctx.Err(), context.Canceled)
						require.Equal(t, remaining, f.m.CountJWTSVIDs())
						rejected := jwtTake(t, jwtStart(context.Background(), f, a, []string{"cached"}))
						require.Equal(t, codes.PermissionDenied, status.Code(rejected.err))
						require.Nil(t, rejected.svid)
						require.Len(t, f.client.snapshot(), 4)
						setUpdate(map[string]*common.RegistrationEntry{"one": a, "two": b}, nil)
						tick()
						replacement := jwtStart(context.Background(), f, a, []string{"pending"})
						require.Len(t, f.client.snapshot(), 5)
						jwtComplete(oldCall, jwtValue(f.clock.Now(), "clean", "obsolete"), nil)
						require.Equal(t, remaining, f.m.CountJWTSVIDs())
						joined := jwtStart(context.Background(), f, a, []string{"pending"})
						require.Len(t, f.client.snapshot(), 5)
						fresh := jwtValue(f.clock.Now(), "clean", "reauthorized")
						jwtComplete(f.client.snapshot()[4], fresh, nil)
						for _, ch := range []<-chan jwtSigningResult{replacement, joined} {
							r := jwtTake(t, ch)
							require.NoError(t, r.err)
							require.Equal(t, fresh, r.svid)
						}
					}
					jwtComplete(stableCall, jwtValue(f.clock.Now(), "clean", "unaffected"), nil)
					if change != "empty" {
						require.NoError(t, jwtTake(t, unaffected).err)
					}
				})
			})
		}
	}
}

func TestJWTRequestCoalescingRotationWindow(t *testing.T) {
	for _, lifetime := range []time.Duration{10 * time.Minute, time.Hour} {
		for _, elapsed := range []time.Duration{lifetime * 2 / 5, lifetime * 3 / 5} {
			t.Run(fmt.Sprintf("lifetime=%s/elapsed=%s", lifetime, elapsed), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := newJWTFixture(t, true, 10)
					entry := jwtEntry("one", 1)
					seed := jwtStart(context.Background(), f, entry, nil)
					value := jwtValue(f.clock.Now(), "clean", "original")
					value.ExpiresAt = value.IssuedAt.Add(lifetime)
					jwtComplete(f.client.snapshot()[0], value, nil)
					require.NoError(t, jwtTake(t, seed).err)
					f.clock.Add(elapsed)
					next := jwtStart(context.Background(), f, entry, nil)
					if elapsed < lifetime/2 {
						require.Len(t, f.client.snapshot(), 1)
						r := jwtTake(t, next)
						require.NoError(t, r.err)
						require.Equal(t, value, r.svid)
					} else {
						require.Len(t, f.client.snapshot(), 2)
						require.True(t, f.client.snapshot()[1].hit)
						fresh := jwtValue(f.clock.Now(), "clean", "refreshed")
						jwtComplete(f.client.snapshot()[1], fresh, nil)
						r := jwtTake(t, next)
						require.NoError(t, r.err)
						require.Equal(t, fresh, r.svid)
					}
				})
			})
		}
	}
}

// Optional pauses at existing telemetry callbacks expose publication races without
// requiring an implementation to emit a particular log or publish metrics first.
type jwtPause struct {
	once    sync.Once
	release sync.Once
	resume  chan struct{}
}

func (p *jwtPause) block()   { p.once.Do(func() { <-p.resume }) }
func (p *jwtPause) unblock() { p.release.Do(func() { close(p.resume) }) }

type jwtPublicationMetrics struct {
	telemetry.Metrics
	armed atomic.Bool
	pause *jwtPause
}

func (m *jwtPublicationMetrics) SetGauge(key []string, val float32) {
	if m.armed.Load() && val > 0 && slices.Equal(key, []string{telemetry.JWTSVIDCacheSize}) {
		m.pause.block()
	}
	m.Metrics.SetGauge(key, val)
}

type jwtPublicationLog struct {
	taint    *jwtPause
	fallback *jwtPause
}

func (*jwtPublicationLog) Levels() []logrus.Level { return logrus.AllLevels }
func (h *jwtPublicationLog) Fire(entry *logrus.Entry) error {
	switch entry.Message {
	case "New tainted JWT authorities found":
		h.taint.block()
	case "Unable to renew JWT; returning cached copy":
		h.fallback.block()
	}
	return nil
}

func TestJWTRequestCoalescingTaintPublication(t *testing.T) {
	for _, outcome := range []string{"signed", "fallback"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				taintPause := &jwtPause{resume: make(chan struct{})}
				publicationPause := &jwtPause{resume: make(chan struct{})}
				defer taintPause.unblock()
				defer publicationPause.unblock()
				var metrics *jwtPublicationMetrics
				f := newJWTFixture(t, true, 10, func(cfg *Config) {
					log, _ := test.NewNullLogger()
					log.SetLevel(logrus.DebugLevel)
					log.AddHook(&jwtPublicationLog{taint: taintPause, fallback: publicationPause})
					cfg.Log = log
					metrics = &jwtPublicationMetrics{Metrics: cfg.Metrics, pause: publicationPause}
					cfg.Metrics = metrics
				})
				entry := jwtEntry("one", 1)
				entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{DisableX509SvidPrefetch: true}
				key, err := x509.MarshalPKIXPublicKey(serverKey.Public())
				require.NoError(t, err)
				bundle := &common.Bundle{TrustDomainId: trustDomain.IDString(),
					JwtSigningKeys: []*common.PublicKey{{Kid: "bad", PkixBytes: key}}}
				f.client.update = &client.Update{Entries: map[string]*common.RegistrationEntry{entry.EntryId: entry},
					Bundles: map[string]*common.Bundle{trustDomain.IDString(): bundle}}
				require.NoError(t, f.m.Initialize(context.Background()))
				if outcome == "fallback" {
					seed := jwtStart(context.Background(), f, entry, nil)
					jwtComplete(f.client.snapshot()[0], jwtValue(f.clock.Now(), "bad", "cached"), nil)
					require.NoError(t, jwtTake(t, seed).err)
					f.clock.Add(50 * time.Minute)
				}
				pending := jwtStart(context.Background(), f, entry, nil)
				calls := f.client.snapshot()
				require.NotEmpty(t, calls)
				call := calls[len(calls)-1]
				bundle.JwtSigningKeys[0].TaintedKey = true
				taintDone := make(chan struct{})
				var taintErr error
				go func() {
					taintErr = f.m.Initialize(context.Background())
					close(taintDone)
				}()
				synctest.Wait()
				taintCompleted := func() bool {
					select {
					case <-taintDone:
						return true
					default:
						return false
					}
				}
				taintedBeforeSigning := taintCompleted()
				metrics.armed.Store(true)
				if outcome == "signed" {
					jwtComplete(call, jwtValue(f.clock.Now(), "bad", "signed"), nil)
				} else {
					jwtComplete(call, nil, errors.New("signing unavailable"))
				}
				var result jwtSigningResult
				returnedBeforeTaint := false
				select {
				case result = <-pending:
					returnedBeforeTaint = true
				default:
				}
				taintPause.unblock()
				// Mutex waits are not durable waits in synctest. Give the taint
				// worker a scheduling window, without requiring it to finish:
				// correct implementations may serialize it behind publication.
				for attempt := 0; attempt < 1000 && !taintCompleted(); attempt++ {
					runtime.Gosched()
				}
				mustReject := taintedBeforeSigning || (taintCompleted() && !returnedBeforeTaint)
				publicationPause.unblock()
				synctest.Wait()
				if !returnedBeforeTaint {
					result = jwtTake(t, pending)
				}
				if mustReject {
					require.Error(t, result.err, "completed taint processing must fence unpublished signing results")
					require.Nil(t, result.svid)
				}
				require.True(t, taintCompleted(), "taint processing did not finish")
				require.NoError(t, taintErr)
				require.Zero(t, f.m.CountJWTSVIDs())
			})
		})
	}
}
