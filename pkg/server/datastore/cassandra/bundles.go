package cassandra

import (
	"context"
	"errors"
	"fmt"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb/pages"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (p *Plugin) AppendBundle(ctx context.Context, req *datastorev1.AppendBundleRequest) (*datastorev1.AppendBundleResponse, error) {
	if req == nil || req.Bundle == nil {
		return nil, errors.New("missing bundle in request")
	}

	existingBundle, err := p.fetchBundle(ctx, req.Bundle.TrustDomainId)
	if err != nil {
		return nil, err
	}

	if existingBundle == nil {
		createResp, err := p.createBundle(ctx, req.Bundle)
		if err != nil {
			return nil, err
		}
		return &datastorev1.AppendBundleResponse{
			Bundle: createResp,
		}, nil
	}

	commonExistingBundle, err := dataToBundle(existingBundle.Data)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal existing bundle: %w", err)
	}

	commonNewBundle, err := dataToBundle(req.Bundle.Data)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal new bundle: %w", err)
	}

	bundle, changed := bundleutil.MergeBundles(commonExistingBundle, commonNewBundle)
	if changed {
		bundle.SequenceNumber++
		newModel, err := bundleToModel(bundle)
		if err != nil {
			return nil, err
		}

		saveQuery := qb.NewUpdate().
			Table("bundles").
			Set("data", newModel.Data).
			Set("updated_at", qb.CqlFunction("toTimestamp(now())")).
			Where("trust_domain", qb.Equals(newModel.TrustDomainId))

		if err = p.db.WriteQuery(saveQuery).ExecContext(ctx); err != nil {
			return nil, newWrappedCassandraError(err)
		}
	}

	commonMergedBundle, err := bundleToModel(bundle)
	if err != nil {
		return nil, err
	}
	return &datastorev1.AppendBundleResponse{
		Bundle: commonMergedBundle,
	}, nil
}

func (p *Plugin) CountBundles(ctx context.Context, _ *datastorev1.CountBundlesRequest) (*datastorev1.CountBundlesResponse, error) {
	countQuery := qb.NewSelect().
		Column("COUNT(*)").
		From("bundles")

	countQ, _ := countQuery.Build()
	var count int32

	execQuery := p.db.session.Query(countQ).Consistency(p.db.cfg.ReadConsistency)
	if err := execQuery.ScanContext(ctx, &count); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.CountBundlesResponse{
		Count: count,
	}, nil
}

func (p *Plugin) CreateBundle(ctx context.Context, req *datastorev1.CreateBundleRequest) (*datastorev1.CreateBundleResponse, error) {
	if req.GetBundle() == nil {
		return nil, errors.New("missing bundle in request")
	}

	exists, err := p.bundleExistsForTrustDomain(ctx, req.Bundle.TrustDomainId)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "bundle with that trust domain ID already exists")
	}

	bundle, err := p.createBundle(ctx, req.Bundle)
	if err != nil {
		return nil, err
	}

	return &datastorev1.CreateBundleResponse{
		Bundle: bundle,
	}, nil
}

func (p *Plugin) DeleteBundle(ctx context.Context, req *datastorev1.DeleteBundleRequest) (*datastorev1.DeleteBundleResponse, error) {
	if req.GetTrustDomain() == "" {
		return nil, errors.New("missing trust domain in request")
	}

	trustDomain := req.GetTrustDomain()

	exists, err := p.bundleExistsForTrustDomain(ctx, trustDomain)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}
	if !exists {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	b := p.db.session.Batch(gocql.LoggedBatch)
	federatedEntries, err := p.findFederatedBundleEntries(ctx, trustDomain)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	switch req.GetMode() {
	case datastorev1.DeleteMode_DELETE_MODE_DELETE:
		for _, fe := range federatedEntries {
			deleteAssociatedQuery := qb.NewDelete().
				From("registered_entries").
				Where("entry_id", qb.Equals(fe.EntryID))
			deleteAssociatedQ, _ := deleteAssociatedQuery.Build()

			b.Entries = append(b.Entries, gocql.BatchEntry{
				Stmt:       deleteAssociatedQ,
				Idempotent: true,
				Args:       deleteAssociatedQuery.QueryValues(),
			})
		}
	case datastorev1.DeleteMode_DELETE_MODE_DISSOCIATE:
		for _, fe := range federatedEntries {
			// remove this trust domain from the federated trust domains lists
			updatedTrustDomainsFull := make([]string, 0, len(fe.TrustDomainsFull))
			for _, td := range fe.TrustDomainsFull {
				if td != trustDomain {
					updatedTrustDomainsFull = append(updatedTrustDomainsFull, td)
				}
			}

			dissociativeUpdateQuery := qb.NewUpdate().
				Table("registered_entries").
				Set("federated_trust_domains_full", updatedTrustDomainsFull).
				Set("federated_trust_domains", updatedTrustDomainsFull).
				Where("entry_id", qb.Equals(fe.EntryID))
			dissociativeUpdateQ, _ := dissociativeUpdateQuery.Build()

			b.Entries = append(b.Entries, gocql.BatchEntry{
				Stmt:       dissociativeUpdateQ,
				Idempotent: true,
				Args:       dissociativeUpdateQuery.QueryValues(),
			})

			deleteEntryRowQuery := qb.NewDelete().
				From("registered_entries").
				Where("entry_id", qb.Equals(fe.EntryID)).
				Where("unrolled_selector_type_val", qb.Equals("")).
				Where("unrolled_ftd", qb.Equals(trustDomain))
			deleteEntryRowQ, _ := deleteEntryRowQuery.Build()

			b.Entries = append(b.Entries, gocql.BatchEntry{
				Stmt:       deleteEntryRowQ,
				Idempotent: true,
				Args:       deleteEntryRowQuery.QueryValues(),
			})
		}
	case datastorev1.DeleteMode_DELETE_MODE_RESTRICT:
		if len(federatedEntries) > 0 {
			return nil, status.Error(
				codes.FailedPrecondition,
				newCassandraError(
					"cannot delete bundle; federated with %d registration entries",
					len(federatedEntries),
				).Error(),
			)
		}
	}

	deleteQuery := qb.NewDelete().
		From("bundles").
		Where("trust_domain", qb.Equals(trustDomain))

	deleteQ, _ := deleteQuery.Build()

	b.Entries = append(b.Entries, gocql.BatchEntry{
		Stmt:       deleteQ,
		Idempotent: true,
		Args:       deleteQuery.QueryValues(),
	})

	if err = b.ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.DeleteBundleResponse{}, nil
}

type federatedEntryRecord struct {
	EntryID              string
	UnrolledTrustDomain  string
	TrustDomainsFull     []string
	TrustDomainsUnrolled []string
}

func (p *Plugin) findFederatedBundleEntries(ctx context.Context, trustDomain string) ([]*federatedEntryRecord, error) {
	federatedEntriesQuery := qb.NewSelect().
		Column("entry_id").
		Column("unrolled_ftd").
		Column("federated_trust_domains_full").
		Column("federated_trust_domains").
		From("registered_entries").
		Where("unrolled_ftd", qb.Equals(trustDomain)).
		AllowFiltering()

	iter := p.db.ReadQuery(federatedEntriesQuery).IterContext(ctx)
	scanner := iter.Scanner()

	entries := []*federatedEntryRecord{}
	for scanner.Next() {
		entry := &federatedEntryRecord{}
		if err := scanner.Scan(
			&entry.EntryID,
			&entry.UnrolledTrustDomain,
			&entry.TrustDomainsFull,
			&entry.TrustDomainsUnrolled,
		); err != nil {
			return nil, newWrappedCassandraError(err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return entries, nil
}

func (p *Plugin) FetchBundle(ctx context.Context, req *datastorev1.FetchBundleRequest) (*datastorev1.FetchBundleResponse, error) {
	bundle, err := p.fetchBundle(ctx, req.GetTrustDomain())
	if err != nil {
		return nil, err
	}

	return &datastorev1.FetchBundleResponse{
		Bundle: bundle,
	}, nil
}

// why duplicate with the public wrapper methods? originally, I _hated_ this from the
// sqlstore implementation, but now I don't think it's so bad, because parameter tuning
// etc (contexts, timeouts, consistency levels) will be easier to accomplish outside the
// interface
func (p *Plugin) fetchBundle(ctx context.Context, trustDomainID string) (*datastorev1.Bundle, error) {
	q := qb.NewSelect().
		Column("data").
		Column("created_at").
		Column("updated_at").
		From("bundles").
		Where("trust_domain", qb.Equals(trustDomainID))

	var (
		data      []byte
		createdAt time.Time
		updatedAt time.Time
	)
	query := p.db.ReadQuery(q)
	if err := query.ScanContext(ctx, &data, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			// The existing datastore implementation does not return an error when no results are found
			return nil, nil
		}

		return nil, fmt.Errorf("Error scanning from bundles: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("No bundle found with trust domain ID %s", trustDomainID)
	}

	return &datastorev1.Bundle{
		TrustDomainId: trustDomainID,
		Data:          data,
		CreatedAt:     createdAt.Unix(),
		UpdatedAt:     updatedAt.Unix(),
	}, nil
}

func dataToBundle(data []byte) (*common.Bundle, error) {
	bundle := new(common.Bundle)
	if err := proto.Unmarshal(data, bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

func (p *Plugin) ListBundles(ctx context.Context, req *datastorev1.ListBundlesRequest) (*datastorev1.ListBundlesResponse, error) {
	pager := pages.NewQueryPaginator(req.GetPagination() != nil, req.GetPagination().GetPageSize(), req.GetPagination().GetPageToken())
	if err := pager.Validate(); err != nil {
		return nil, err
	}

	q := qb.NewSelect().
		Distinct().
		From("bundles").
		Column("trust_domain").
		Column("data")

	selectStmt, _ := q.Build()

	resp := &datastorev1.ListBundlesResponse{
		Bundles: make([]*datastorev1.Bundle, 0),
	}
	query := p.db.session.Query(selectStmt).Consistency(gocql.Serial)
	pager.BindToQuery(query)

	iter := query.IterContext(ctx)
	pager.ForIter(iter)
	scanner := iter.Scanner()

	for scanner.Next() {
		b := new(datastorev1.Bundle)
		if err := scanner.Scan(&b.TrustDomainId, &b.Data); err != nil {
			return nil, newWrappedCassandraError(err)
		}

		resp.Bundles = append(resp.Bundles, b)
	}
	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	resp.Pagination = responsePaginationFromPager(pager)

	return resp, nil
}

func (p *Plugin) PruneBundle(ctx context.Context, req *datastorev1.PruneBundleRequest) (*datastorev1.PruneBundleResponse, error) {
	if req == nil || req.GetTrustDomain() == "" {
		return nil, errors.New("missing trust domain ID in request")
	}

	trustDomainID := req.GetTrustDomain()
	expiresBefore := time.Unix(int64(req.GetExpiresBefore()), 0)

	currentBundle, err := p.fetchBundle(ctx, trustDomainID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch current bundle: %w", err)
	}

	if currentBundle == nil {
		return nil, nil
	}

	commonCurrentBundle, err := dataToBundle(currentBundle.Data)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal current bundle: %w", err)
	}

	newBundle, changed, err := bundleutil.PruneBundle(commonCurrentBundle, expiresBefore, p.log)
	if err != nil {
		return nil, fmt.Errorf("prune failed: %w", err)
	}

	if changed {
		newBundle.SequenceNumber = commonCurrentBundle.SequenceNumber + 1
		modelNewBundle, err := bundleToModel(newBundle)
		if err != nil {
			return nil, fmt.Errorf("unable to convert pruned bundle to model: %w", err)
		}

		if _, err = p.updateBundle(ctx, &datastorev1.UpdateBundleRequest{
			Bundle: modelNewBundle,
			Mask:   AllTrueBundleMask,
		}); err != nil {
			return nil, fmt.Errorf("unable to write new bundle: %w", err)
		}
	}

	return &datastorev1.PruneBundleResponse{Changed: changed}, nil
}

func (p *Plugin) bundleExistsForTrustDomain(ctx context.Context, trustDomainID string) (bool, error) {
	var count int
	existsQ := `
	SELECT COUNT(*)
	FROM bundles	
	WHERE trust_domain = ?`

	query := p.db.session.Query(existsQ, trustDomainID).Consistency(gocql.Serial)
	if err := query.ScanContext(ctx, &count); err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return false, nil
		}

		return false, err
	}

	return count > 0, nil
}

func (p *Plugin) SetBundle(ctx context.Context, req *datastorev1.SetBundleRequest) (*datastorev1.SetBundleResponse, error) {
	if req == nil || req.Bundle == nil {
		return nil, errors.New("missing bundle in request")
	}

	exists, err := p.bundleExistsForTrustDomain(ctx, req.Bundle.TrustDomainId)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	if !exists {
		bundle, err := p.createBundle(ctx, req.Bundle)
		if err != nil {
			return nil, err
		}
		return &datastorev1.SetBundleResponse{Bundle: bundle}, nil
	}

	bundle, err := p.updateBundle(ctx, &datastorev1.UpdateBundleRequest{
		Bundle: req.Bundle,
		Mask:   AllTrueBundleMask,
	})
	if err != nil {
		return nil, err
	}
	return &datastorev1.SetBundleResponse{Bundle: bundle.Bundle}, nil
}

func (p *Plugin) createBundle(ctx context.Context, newBundle *datastorev1.Bundle) (*datastorev1.Bundle, error) {
	// The Bundle will always have a row set with an empty federated_entry_id.
	// This allows federation relationships to come and go without impacting the bundle data itself,
	// and simplifies query patterns.
	createQ := `
	INSERT INTO bundles (created_at, updated_at, trust_domain, data, federated_entry_id)
	VALUES (toTimestamp(now()), toTimestamp(now()), ?, ?, '')
	`
	query := p.db.session.Query(createQ, newBundle.TrustDomainId, newBundle.Data).Consistency(p.db.cfg.WriteConsistency)

	err := query.ExecContext(ctx)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return newBundle, nil
}

func (p *Plugin) updateBundle(ctx context.Context, req *datastorev1.UpdateBundleRequest) (*datastorev1.UpdateBundleResponse, error) {
	existingModel := &datastorev1.Bundle{}
	readQ := `
	SELECT DISTINCT created_at, updated_at, trust_domain, data
	FROM bundles WHERE trust_domain = ?
	`

	query := p.db.session.Query(readQ, req.Bundle.TrustDomainId).Consistency(gocql.Serial)
	if err := query.ScanContext(
		ctx,
		&existingModel.CreatedAt,
		&existingModel.UpdatedAt,
		&existingModel.TrustDomainId,
		&existingModel.Data,
	); err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return nil, status.Error(codes.NotFound, NotFoundErr.Error())
		}

		return nil, newCassandraError("could not read existing bundle: %s", err.Error())
	}

	newBundle, err := dataToBundle(req.Bundle.Data)
	if err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to unmarshal new bundle: %w", err))
	}
	existingBundle, err := dataToBundle(existingModel.Data)
	if err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to unmarshal existing bundle: %w", err))
	}

	inputMask := req.GetMask()
	if req.GetMask() == nil {
		inputMask = AllTrueBundleMask
	}

	if inputMask.RefreshHint {
		existingBundle.RefreshHint = newBundle.RefreshHint
	}

	if inputMask.RootCas {
		existingBundle.RootCas = newBundle.RootCas
	}

	if inputMask.JwtSigningKeys {
		existingBundle.JwtSigningKeys = newBundle.JwtSigningKeys
	}

	if inputMask.SequenceNumber {
		existingBundle.SequenceNumber = newBundle.SequenceNumber
	}

	if inputMask.WitSigningKeys {
		existingBundle.WitSigningKeys = newBundle.WitSigningKeys
	}

	// TODO(tjons): why do we not check X509TaintedKeys in the mask?

	modelDataToSave, err := bundleToModel(existingBundle)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	updateQ := `
	UPDATE bundles 
	SET updated_at = toTimestamp(now()),
		data = ?
	WHERE trust_domain = ?
	`
	query = p.db.session.Query(updateQ, modelDataToSave.Data, modelDataToSave.TrustDomainId).Consistency(p.db.cfg.WriteConsistency)
	if err = query.ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	finalBundle, err := p.fetchBundle(ctx, req.GetBundle().GetTrustDomainId())
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.UpdateBundleResponse{Bundle: finalBundle}, nil
}

var AllTrueBundleMask = &datastorev1.BundleMask{
	RootCas:         true,
	JwtSigningKeys:  true,
	RefreshHint:     true,
	SequenceNumber:  true,
	X509TaintedKeys: true,
	WitSigningKeys:  true,
}

func applyBundleMask(model *datastorev1.Bundle, newBundle *common.Bundle, inputMask *datastorev1.BundleMask) ([]byte, *common.Bundle, error) {
	bundle, err := dataToBundle(model.Data)
	if err != nil {
		return nil, nil, err
	}

	if inputMask == nil {
		inputMask = AllTrueBundleMask
	}

	if inputMask.RefreshHint {
		bundle.RefreshHint = newBundle.RefreshHint
	}

	if inputMask.RootCas {
		bundle.RootCas = newBundle.RootCas
	}

	if inputMask.JwtSigningKeys {
		bundle.JwtSigningKeys = newBundle.JwtSigningKeys
	}

	if inputMask.SequenceNumber {
		bundle.SequenceNumber = newBundle.SequenceNumber
	}

	newModel, err := bundleToModel(bundle)
	if err != nil {
		return nil, nil, err
	}

	return newModel.Data, bundle, nil
}

func (p *Plugin) UpdateBundle(ctx context.Context, req *datastorev1.UpdateBundleRequest) (*datastorev1.UpdateBundleResponse, error) {
	return p.updateBundle(ctx, req)
}

func bundleToModel(pb *common.Bundle) (*datastorev1.Bundle, error) {
	if pb == nil {
		return nil, newCassandraError("missing bundle in request")
	}

	data, err := proto.Marshal(pb)
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.Bundle{
		TrustDomainId: pb.TrustDomainId,
		Data:          data,
	}, nil
}
