package sqlstorev2

import (
	"context"
	"errors"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/gorm"
)

// CreateJoinToken takes a Token message and stores it
func (ds *Plugin) CreateJoinToken(ctx context.Context, token *datastore.JoinToken) (err error) {
	if token == nil || token.Token == "" || token.Expiry.IsZero() {
		return errors.New("token and expiry are required")
	}

	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return createJoinToken(tx, token)
	})
}

// FetchJoinToken takes a Token message and returns one, populating the fields
// we have knowledge of. If the token is not found, nil is returned.
func (ds *Plugin) FetchJoinToken(ctx context.Context, token string) (resp *datastore.JoinToken, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = fetchJoinToken(tx, token)
		return err
	}); err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteJoinToken deletes the given join token
func (ds *Plugin) DeleteJoinToken(ctx context.Context, token string) error {
	return ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) error {
		return deleteJoinToken(tx, token)
	})
}

// PruneJoinTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (ds *Plugin) PruneJoinTokens(ctx context.Context, expiry time.Time) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return pruneJoinTokens(tx, expiry)
	})
}

func createJoinToken(tx *gorm.DB, token *datastore.JoinToken) error {
	t := JoinToken{
		Token:  token.Token,
		Expiry: token.Expiry.Unix(),
	}

	if err := tx.Create(&t).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	return nil
}

func fetchJoinToken(tx *gorm.DB, token string) (*datastore.JoinToken, error) {
	var model JoinToken
	err := tx.Where("token = ?", token).Take(&model).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToJoinToken(model), nil
}

func deleteJoinToken(tx *gorm.DB, token string) error {
	var model JoinToken
	if err := tx.Where("token = ?", token).Take(&model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	result := tx.Delete(&model)
	if result.Error != nil {
		return sqlcommon.NewWrappedSQLError(result.Error)
	}

	if result.RowsAffected != 1 {
		return sqlcommon.NewSQLError("expected to delete one row, but %d rows were affected", result.RowsAffected)
	}

	return nil
}

func pruneJoinTokens(tx *gorm.DB, expiresBefore time.Time) error {
	if err := tx.Where("expiry < ?", expiresBefore.Unix()).Delete(&JoinToken{}).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	return nil
}

func modelToJoinToken(model JoinToken) *datastore.JoinToken {
	return &datastore.JoinToken{
		Token:  model.Token,
		Expiry: time.Unix(model.Expiry, 0),
	}
}
