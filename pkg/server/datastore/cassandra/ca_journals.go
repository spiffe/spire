package cassandra

import (
	"context"
	"errors"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/sirupsen/logrus"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/private/server/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type CAJournal struct {
	ID                    uint
	ActiveX509AuthorityID string
	JournalData           []byte
}

func (p *Plugin) nextCAJournalID(ctx context.Context) (uint, error) {
	createQ := `SELECT MAX(id) FROM ca_journals ALLOW FILTERING`
	var maxID uint
	if err := p.db.session.Query(createQ).Consistency(p.db.cfg.WriteConsistency).ScanContext(ctx, &maxID); err != nil {
		return 0, err
	}
	return maxID + 1, nil
}

func (p *Plugin) SetCAJournal(ctx context.Context, req *datastorev1.SetCAJournalRequest) (*datastorev1.SetCAJournalResponse, error) {
	if req == nil || req.GetJournal() == nil {
		return nil, status.Error(codes.InvalidArgument, "ca journal is required")
	}
	caJournal := req.GetJournal()

	if err := validateCAJournal(caJournal); err != nil {
		return nil, err
	}

	var (
		journal *datastorev1.CAJournal
		err     error
	)
	if caJournal.Id == 0 {
		journal, err = p.createCAJournal(ctx, caJournal)
	} else {
		journal, err = p.updateCAJournal(ctx, caJournal)
	}

	return &datastorev1.SetCAJournalResponse{
		Journal: journal,
	}, err
}

func (p *Plugin) updateCAJournal(ctx context.Context, caJournal *datastorev1.CAJournal) (*datastorev1.CAJournal, error) {
	updateQ := `UPDATE ca_journals SET
		active_x509_authority_id = ?,
		data = ?,
		updated_at = toTimestamp(now())
		WHERE id = ? IF EXISTS`

	res := make(map[string]any)
	applied, err := p.db.session.Query(updateQ,
		caJournal.GetActiveX509AuthorityId(),
		caJournal.GetData(),
		caJournal.GetId(),
	).Consistency(p.db.cfg.WriteConsistency).MapScanCAS(res)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update CA journal: %v", err)
	}

	if !applied {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	return p.fetchCAJournalByID(ctx, caJournal.GetId())
}

func (p *Plugin) createCAJournal(ctx context.Context, caJournal *datastorev1.CAJournal) (*datastorev1.CAJournal, error) {
	nextId, err := p.nextCAJournalID(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get next CA journal ID: %v", err)
	}

	createQ := `INSERT INTO ca_journals (
		id,
		active_x509_authority_id,
		data,
		created_at,
		updated_at
	) VALUES (?, ?, ?, toTimestamp(now()), toTimestamp(now())) IF NOT EXISTS`

	if err := p.db.session.Query(createQ,
		nextId,
		caJournal.GetActiveX509AuthorityId(),
		caJournal.GetData(),
	).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to insert CA journal: %v", err)
	}

	caJournal.Id = uint64(nextId)

	return caJournal, nil
}

func (p *Plugin) fetchCAJournalByID(ctx context.Context, id uint64) (*datastorev1.CAJournal, error) {
	findQ := `SELECT
		id,
		active_x509_authority_id,
		data
		FROM ca_journals
		WHERE id = ?`

	var caJournal datastorev1.CAJournal
	if err := p.db.session.Query(findQ, id).Consistency(p.db.cfg.ReadConsistency).ScanContext(
		ctx,
		&caJournal.Id,
		&caJournal.ActiveX509AuthorityId,
		&caJournal.Data,
	); err != nil {
		return nil, err
	}

	return &caJournal, nil
}

func (p *Plugin) fetchCAJournalByActiveX509AuthorityID(ctx context.Context, activeX509AuthorityID string) (*datastorev1.CAJournal, error) {
	findQ := `SELECT
		id,
		active_x509_authority_id,
		data
		FROM ca_journals
		WHERE active_x509_authority_id = ? LIMIT 1`

	var caJournal datastorev1.CAJournal
	if err := p.db.session.Query(findQ, activeX509AuthorityID).Consistency(p.db.cfg.ReadConsistency).ScanContext(
		ctx,
		&caJournal.Id,
		&caJournal.ActiveX509AuthorityId,
		&caJournal.Data,
	); err != nil {
		return nil, err
	}

	return &caJournal, nil
}

func (p *Plugin) FetchCAJournal(ctx context.Context, req *datastorev1.FetchCAJournalRequest) (*datastorev1.FetchCAJournalResponse, error) {
	if req.GetActiveX509AuthorityId() == "" {
		return nil, status.Error(codes.InvalidArgument, "active X509 authority ID is required")
	}

	j, err := p.fetchCAJournalByActiveX509AuthorityID(ctx, req.GetActiveX509AuthorityId())
	if err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return &datastorev1.FetchCAJournalResponse{
		Journal: j,
	}, nil
}

func (p *Plugin) PruneCAJournals(ctx context.Context, req *datastorev1.PruneCAJournalsRequest) (*datastorev1.PruneCAJournalsResponse, error) {
	journals, err := p.listCAJournals(ctx)
	if err != nil {
		return nil, err
	}

checkAuthorities:
	for _, model := range journals {
		entries := new(journal.Entries)
		if err := proto.Unmarshal(model.Data, entries); err != nil {
			return nil, status.Errorf(codes.Internal, "unable to unmarshal entries from CA journal record: %v", err)
		}

		for _, x509CA := range entries.X509CAs {
			if x509CA.NotAfter > int64(req.GetExpiresBefore()) {
				continue checkAuthorities
			}
		}

		for _, jwtKey := range entries.JwtKeys {
			if jwtKey.NotAfter > int64(req.GetExpiresBefore()) {
				continue checkAuthorities
			}
		}

		if err := p.deleteCAJournal(ctx, model.Id); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to delete CA journal: %v", err)
		}

		p.log.WithFields(logrus.Fields{
			telemetry.CAJournalID: model.Id,
		}).Info("Pruned stale CA journal record")
	}

	return &datastorev1.PruneCAJournalsResponse{}, nil
}

func (p *Plugin) deleteCAJournal(ctx context.Context, id uint64) error {
	deleteQ := `DELETE FROM ca_journals WHERE id = ? IF EXISTS`

	if err := p.db.session.Query(deleteQ, id).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return status.Errorf(codes.Internal, "failed to delete CA journal: %v", err)
	}

	return nil
}

func (p *Plugin) ListCAJournals(ctx context.Context, req *datastorev1.ListCAJournalsRequest) (*datastorev1.ListCAJournalsResponse, error) {
	journals, err := p.listCAJournals(ctx)
	if err != nil {
		return nil, err
	}

	return &datastorev1.ListCAJournalsResponse{
		Journals: journals,
	}, nil
}

func (p *Plugin) listCAJournals(ctx context.Context) ([]*datastorev1.CAJournal, error) {
	listQ := `SELECT
		id,
		active_x509_authority_id,
		data
		FROM ca_journals`

	var caJournals []*datastorev1.CAJournal
	scanner := p.db.session.Query(listQ).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx).Scanner()
	for scanner.Next() {
		caJournal := new(datastorev1.CAJournal)

		if err := scanner.Scan(
			&caJournal.Id,
			&caJournal.ActiveX509AuthorityId,
			&caJournal.Data,
		); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to scan CA journal: %v", err)
		}
		caJournals = append(caJournals, caJournal)
	}
	if err := scanner.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to iterate CA journals: %v", err)
	}

	return caJournals, nil
}

// TODO(tjons): copied from pkg/server/datastore/sqlstore/sqlstore.go:4935. unify this.
func validateCAJournal(caJournal *datastorev1.CAJournal) error {
	if caJournal == nil {
		return status.Error(codes.InvalidArgument, "ca journal is required")
	}

	return nil
}
