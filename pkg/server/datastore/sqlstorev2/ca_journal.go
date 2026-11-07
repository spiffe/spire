package sqlstorev2

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/proto/private/server/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

// FetchCAJournal fetches the CA journal that has the given active X509
// authority domain. If the CA journal is not found, nil is returned.
func (ds *Plugin) FetchCAJournal(ctx context.Context, activeX509AuthorityID string) (caJournal *datastore.CAJournal, err error) {
	if activeX509AuthorityID == "" {
		return nil, status.Error(codes.InvalidArgument, "active X509 authority ID is required")
	}

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		caJournal, err = fetchCAJournal(tx, activeX509AuthorityID)
		return err
	}); err != nil {
		return nil, err
	}

	return caJournal, nil
}

// ListCAJournalsForTesting returns all the CA journal records, and is meant to
// be used in tests.
func (ds *Plugin) ListCAJournalsForTesting(ctx context.Context) (caJournals []*datastore.CAJournal, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		caJournals, err = listCAJournalsForTesting(tx)
		return err
	}); err != nil {
		return nil, err
	}
	return caJournals, nil
}

// SetCAJournal sets the content for the specified CA journal. If the CA journal
// does not exist, it is created.
func (ds *Plugin) SetCAJournal(ctx context.Context, caJournal *datastore.CAJournal) (caj *datastore.CAJournal, err error) {
	if err := validateCAJournal(caJournal); err != nil {
		return nil, err
	}

	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		if caJournal.ID == 0 {
			caj, err = createCAJournal(tx, caJournal)
			return err
		}

		// The CA journal already exists, update it.
		caj, err = updateCAJournal(tx, caJournal)
		return err
	}); err != nil {
		return nil, err
	}
	return caj, nil
}

// PruneCAJournals prunes the CA journals that have all of their authorities
// expired.
func (ds *Plugin) PruneCAJournals(ctx context.Context, allAuthoritiesExpireBefore int64) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return ds.pruneCAJournals(tx, allAuthoritiesExpireBefore)
	})
}

func (ds *Plugin) pruneCAJournals(tx *gorm.DB, allAuthoritiesExpireBefore int64) error {
	var caJournals []CAJournal
	if err := tx.Find(&caJournals).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

checkAuthorities:
	for _, model := range caJournals {
		entries := new(journal.Entries)
		if err := proto.Unmarshal(model.Data, entries); err != nil {
			return status.Errorf(codes.Internal, "unable to unmarshal entries from CA journal record: %v", err)
		}

		for _, x509CA := range entries.X509CAs {
			if x509CA.NotAfter > allAuthoritiesExpireBefore {
				continue checkAuthorities
			}
		}
		for _, jwtKey := range entries.JwtKeys {
			if jwtKey.NotAfter > allAuthoritiesExpireBefore {
				continue checkAuthorities
			}
		}
		if err := deleteCAJournal(tx, model.ID); err != nil {
			return status.Errorf(codes.Internal, "failed to delete CA journal: %v", err)
		}
		ds.log.WithFields(logrus.Fields{
			telemetry.CAJournalID: model.ID,
		}).Info("Pruned stale CA journal record")
	}

	return nil
}

func modelToCAJournal(model CAJournal) *datastore.CAJournal {
	return &datastore.CAJournal{
		ID:                    model.ID,
		Data:                  model.Data,
		ActiveX509AuthorityID: model.ActiveX509AuthorityID,
	}
}

// createCAJournal omits journal_id, which databases at schema versions before
// 26 do not have.
func createCAJournal(tx *gorm.DB, caJournal *datastore.CAJournal) (*datastore.CAJournal, error) {
	model := CAJournal{
		Data:                  caJournal.Data,
		ActiveX509AuthorityID: caJournal.ActiveX509AuthorityID,
	}

	if err := tx.Omit("journal_id").Create(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToCAJournal(model), nil
}

func fetchCAJournal(tx *gorm.DB, activeX509AuthorityID string) (*datastore.CAJournal, error) {
	var model CAJournal
	err := tx.Where("active_x509_authority_id = ?", activeX509AuthorityID).Take(&model).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToCAJournal(model), nil
}

func listCAJournalsForTesting(tx *gorm.DB) (caJournals []*datastore.CAJournal, err error) {
	var caJournalsModel []CAJournal
	if err := tx.Find(&caJournalsModel).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	for _, model := range caJournalsModel {
		caJournals = append(caJournals, modelToCAJournal(model))
	}
	return caJournals, nil
}

// updateCAJournal writes only the columns SetCAJournal owns, leaving
// journal_id untouched since databases at schema versions before 26 do not
// have it.
func updateCAJournal(tx *gorm.DB, caJournal *datastore.CAJournal) (*datastore.CAJournal, error) {
	var model CAJournal
	if err := tx.Where("id = ?", caJournal.ID).Take(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	model.ActiveX509AuthorityID = caJournal.ActiveX509AuthorityID
	model.Data = caJournal.Data

	if err := tx.Model(&model).Select("active_x509_authority_id", "data", "updated_at").Updates(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToCAJournal(model), nil
}

func validateCAJournal(caJournal *datastore.CAJournal) error {
	if caJournal == nil {
		return status.Error(codes.InvalidArgument, "ca journal is required")
	}

	return nil
}

func deleteCAJournal(tx *gorm.DB, caJournalID uint) error {
	model := new(CAJournal)
	if err := tx.Where("id = ?", caJournalID).Take(model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	if err := tx.Delete(model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}
