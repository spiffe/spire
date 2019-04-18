//go:generate github.com/spiffe/spire/proto/spire/server/nodeattestor NodeAttestor
//go:generate github.com/spiffe/spire/proto/spire/server/datastore DataStore
//go:generate github.com/spiffe/spire/proto/spire/server/upstreamca UpstreamCA
//go:generate github.com/spiffe/spire/proto/spire/server/noderesolver NodeResolver
//go:generate github.com/spiffe/spire/proto/spire/server/keymanager KeyManager
package interfaces
