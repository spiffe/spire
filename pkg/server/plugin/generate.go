//go:generate github.com/spiffe/spire/proto/server/nodeattestor NodeAttestor
//go:generate github.com/spiffe/spire/proto/server/datastore DataStore
//go:generate github.com/spiffe/spire/proto/server/upstreamca UpstreamCA
//go:generate github.com/spiffe/spire/proto/server/noderesolver NodeResolver
//go:generate github.com/spiffe/spire/proto/server/keymanager KeyManager
package interfaces
