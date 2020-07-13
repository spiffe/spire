package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	agentpb "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	bundlepb "github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	entrypb "github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	svidpb "github.com/spiffe/spire/proto/spire-next/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
)

func (c *client) fetchUpdates(ctx context.Context, req *node.FetchX509SVIDRequest, forRotation bool) (*Update, error) {
	protoEntries, err := c.fetchEntries(ctx)
	if err != nil {
		return nil, err
	}

	regEntries := make(map[string]*common.RegistrationEntry)
	federatesWith := make(map[string]bool)
	for _, e := range protoEntries {
		entry, err := registrationEntryFromProto(e)
		if err != nil {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: e.Id,
				telemetry.SPIFFEID:       e.SpiffeId,
				telemetry.Selectors:      e.Selectors,
				telemetry.Error:          err.Error(),
			}).Warn("Received malformed entry from SPIRE server")
			continue
		}

		c.c.Log.WithField("entryID", entry.EntryId).WithField("spiffeID", entry.SpiffeId).Debug("Entry found")
		// Get all federated trust domains
		for _, td := range entry.FederatesWith {
			federatesWith[td] = true
		}
		regEntries[entry.EntryId] = entry
	}

	keys := make([]string, 0, len(federatesWith))
	for key := range federatesWith {
		keys = append(keys, key)
	}
	protoBundles, err := c.fetchBundles(ctx, keys)
	if err != nil {
		return nil, err
	}

	bundles := make(map[string]*common.Bundle)
	for _, b := range protoBundles {
		bundle, err := bundleFormProto(b)
		if err != nil {
			c.c.Log.WithError(err).WithField(telemetry.TrustDomainID, b.TrustDomain).Warn("Received malformed entry from SPIRE server")
		}
		bundles[b.TrustDomain] = bundle
	}

	svids := make(map[string]*node.X509SVID)
	switch {
	case len(req.Csrs) == 0:
		// No action need
	case forRotation:
		for spiffID, csr := range req.Csrs {
			svid, err := c.renewSVID(ctx, csr)
			if err != nil {
				return nil, err
			}

			var certChain []byte
			for _, cert := range svid.CertChain {
				certChain = append(certChain, cert...)
			}
			svids[spiffID] = &node.X509SVID{
				CertChain: certChain,
				ExpiresAt: svid.ExpiresAt,
			}
		}
	default:
		var params []*svidpb.NewX509SVIDParams
		for entryID, csr := range req.Csrs {
			params = append(params, &svidpb.NewX509SVIDParams{
				EntryId: entryID,
				Csr:     csr,
			})
		}

		protoSvids, err := c.fetchSVIDs(ctx, params)
		if err != nil {
			return nil, err
		}

		for i, s := range protoSvids {
			entryID := params[i].EntryId
			if s == nil {
				c.c.Log.WithField(telemetry.RegistrationID, entryID).Debug("Entry not found")
				continue
			}
			var certChain []byte
			for _, cert := range s.CertChain {
				certChain = append(certChain, cert...)
			}

			svids[entryID] = &node.X509SVID{
				CertChain: certChain,
				ExpiresAt: s.ExpiresAt,
			}
		}
	}

	return &Update{
		Entries: regEntries,
		Bundles: bundles,
		SVIDs:   svids,
	}, nil
}

func (c *client) fetchEntries(ctx context.Context) ([]*types.Entry, error) {
	entryClient, connection, err := c.newEntryClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := entryClient.GetAuthorizedEntries(ctx, &entrypb.GetAuthorizedEntriesRequest{})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to fetch authorized entries")
		return nil, errors.New("failed to fetch authorized entries")
	}

	return resp.Entries, err
}

func (c *client) fetchBundles(ctx context.Context, federatedBundles []string) ([]*types.Bundle, error) {
	bundleClient, connection, err := c.newBundleClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	var bundles []*types.Bundle

	// Get bundle
	bundle, err := bundleClient.GetBundle(ctx, &bundlepb.GetBundleRequest{})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("Failed to fetch bundle")
		return nil, errors.New("failed to fetch bundle")
	}
	bundles = append(bundles, bundle)

	for _, b := range federatedBundles {
		bundle, err := bundleClient.GetFederatedBundle(ctx, &bundlepb.GetFederatedBundleRequest{
			TrustDomain: b,
		})
		if err != nil {
			// TODO: may it continue or just return error?
			c.c.Log.WithError(err).WithField(telemetry.FederatedBundle, b).Warn("Faied to fetch federated bundle")
			continue
		}
		bundles = append(bundles, bundle)
	}

	return bundles, nil
}

// TODO: this implementation must be refactored once we remove ACK logic (#1723) and covered with unit tests
func (c *client) renewSVID(ctx context.Context, csr []byte) (*types.X509SVID, error) {
	agentClient, connection, err := c.newAgentClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	stream, err := agentClient.RenewAgent(ctx)
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("failed to renew connection")
		return nil, err
	}

	req := &agentpb.RenewAgentRequest{
		Step: &agentpb.RenewAgentRequest_Params{
			Params: &agentpb.AgentX509SVIDParams{
				Csr: csr,
			},
		},
	}
	if err := stream.Send(req); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	req = &agentpb.RenewAgentRequest{
		Step: &agentpb.RenewAgentRequest_Ack_{Ack: &agentpb.RenewAgentRequest_Ack{}},
	}
	if err := stream.Send(req); err != nil {
		return nil, err
	}
	if _, err := stream.Recv(); err != io.EOF {
		return nil, err
	}

	return resp.Svid, nil
}

func (c *client) fetchSVIDs(ctx context.Context, params []*svidpb.NewX509SVIDParams) ([]*types.X509SVID, error) {
	svidClient, connection, err := c.newSVIDClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.BatchNewX509SVID(ctx, &svidpb.BatchNewX509SVIDRequest{
		Params: params,
	})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Error("failed to batch svid")
		return nil, errors.New("failed to batch svid")
	}

	okStatus := int32(codes.OK)
	var svids []*types.X509SVID
	for i, r := range resp.Results {
		if r.Status.Code != okStatus {
			c.c.Log.WithFields(logrus.Fields{
				telemetry.RegistrationID: params[i].EntryId,
				telemetry.Status:         r.Status.Code,
				telemetry.Error:          r.Status.Message,
			}).Warn("Fails to mint X509 SVID")
		}

		svids = append(svids, r.Bundle)
	}

	return svids, nil
}

func (c *client) fetchJWTSVID(ctx context.Context, jsr *node.JSR, entryID string) (*JWTSVID, error) {
	svidClient, connection, err := c.newSVIDClient(ctx)
	if err != nil {
		return nil, err
	}
	defer connection.Release()

	resp, err := svidClient.NewJWTSVID(ctx, &svidpb.NewJWTSVIDRequest{
		Audience: jsr.Audience,
		EntryId:  entryID,
	})
	if err != nil {
		c.release(connection)
		c.c.Log.WithError(err).Errorf("Failure fetching JWT SVID")
		return nil, fmt.Errorf("failure fetching JWT SVID: %v", err)
	}

	svid := resp.Svid
	switch {
	case svid == nil:
		return nil, errors.New("JWTSVID response missing SVID")
	case svid.IssuedAt == 0:
		return nil, errors.New("JWTSVID missing issued at")
	case svid.ExpiresAt == 0:
		return nil, errors.New("JWTSVID missing expires at")
	case svid.IssuedAt > svid.ExpiresAt:
		return nil, errors.New("JWTSVID issued after it has expired")
	}

	return &JWTSVID{
		Token:     svid.Token,
		IssuedAt:  time.Unix(svid.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(svid.ExpiresAt, 0).UTC(),
	}, nil
}

func (c *client) newEntryClient(ctx context.Context) (entrypb.EntryClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	// open a new connection
	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewEntryClient(c.connections.conn), c.connections, nil
}

func (c *client) newBundleClient(ctx context.Context) (bundlepb.BundleClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	// open a new connection
	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewBundleClient(c.connections.conn), c.connections, nil
}

func (c *client) newSVIDClient(ctx context.Context) (svidpb.SVIDClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	// open a new connection
	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewSVIDClient(c.connections.conn), c.connections, nil
}

func (c *client) newAgentClient(ctx context.Context) (agentpb.AgentClient, *nodeConn, error) {
	c.m.Lock()
	defer c.m.Unlock()

	// open a new connection
	if c.connections == nil {
		conn, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.connections = newNodeConn(conn)
	}
	c.connections.AddRef()
	return c.createNewAgentClient(c.connections.conn), c.connections, nil
}
