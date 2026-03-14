package cassandra

import (
	"context"
	"errors"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/tjons/cassandra-toolbox/qb"
)

func (p *Plugin) CreateJoinToken(
	ctx context.Context,
	req *datastorev1.CreateJoinTokenRequest,
) (*datastorev1.CreateJoinTokenResponse, error) {
	if req == nil || req.Token == "" || req.ExpiresAt == 0 {
		return nil, errors.New("token and expiry are required")
	}

	jt, err := p.FetchJoinToken(ctx, &datastorev1.FetchJoinTokenRequest{Token: req.Token})
	if err != nil {
		return nil, err
	}
	if jt != nil {
		return nil, newWrappedCassandraError(errors.New("join token already exists"))
	}

	// TODO (tjons): this query could really really benefit from an LWT
	createQuery := qb.NewInsert().
		Into("join_tokens").
		Columns("join_token", "expiry").
		Values(req.Token, req.ExpiresAt)
	if err = p.db.WriteQuery(createQuery).ExecContext(ctx); err != nil {
		return nil, err
	}

	return &datastorev1.CreateJoinTokenResponse{}, nil
}

func (p *Plugin) DeleteJoinToken(
	ctx context.Context,
	req *datastorev1.DeleteJoinTokenRequest,
) (*datastorev1.DeleteJoinTokenResponse, error) {
	jt, err := p.FetchJoinToken(ctx, &datastorev1.FetchJoinTokenRequest{Token: req.Token})
	if err != nil {
		return nil, err
	}
	if jt == nil {
		return nil, newWrappedCassandraError(errors.New("join token not found"))
	}

	// TODO (tjons): this could really really benefit from an LWT
	deleteQuery := qb.NewDelete().From("join_tokens").Where("join_token", qb.Equals(req.Token))
	if err = p.db.WriteQuery(deleteQuery).ExecContext(ctx); err != nil {
		return nil, err
	}

	return &datastorev1.DeleteJoinTokenResponse{}, nil
}

func (p *Plugin) FetchJoinToken(
	ctx context.Context,
	req *datastorev1.FetchJoinTokenRequest,
) (*datastorev1.FetchJoinTokenResponse, error) {
	var (
		jt  string
		exp int64
	)

	findQuery := qb.NewSelect().
		From("join_tokens").
		Where("join_token", qb.Equals(req.Token))

	if err := p.db.ReadQuery(findQuery).ScanContext(ctx, &jt, &exp); err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return &datastorev1.FetchJoinTokenResponse{
		Token:     jt,
		ExpiresAt: exp,
	}, nil
}

func (p *Plugin) PruneJoinTokens(
	ctx context.Context,
	req *datastorev1.PruneJoinTokensRequest,
) (*datastorev1.PruneJoinTokensResponse, error) {
	findExpiredQuery := qb.NewSelect().
		From("join_tokens").
		Column("join_token").
		Where("expiry", qb.LessThan(req.ExpiresBefore)).
		AllowFiltering()

	scanner := p.db.ReadQuery(findExpiredQuery).IterContext(ctx).Scanner()
	expiredTokens := make([]any, 0)
	for scanner.Next() {
		var token string
		if err := scanner.Scan(&token); err != nil {
			return nil, err
		}
		expiredTokens = append(expiredTokens, token)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(expiredTokens) > 0 {
		q := qb.NewDelete().From("join_tokens").Where("join_token", qb.In(expiredTokens...))
		if err := p.db.WriteQuery(q).ExecContext(ctx); err != nil {
			return nil, err
		}
	}

	return &datastorev1.PruneJoinTokensResponse{}, nil
}
