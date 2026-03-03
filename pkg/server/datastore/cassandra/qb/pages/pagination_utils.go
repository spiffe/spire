package pages

import (
	"encoding/base64"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type QueryPaginator struct {
	PageSize  int32
	PageToken string
	iter      *gocql.Iter
}

func NewQueryPaginator(usePaginator bool, pageSize int32, pageToken string) *QueryPaginator {
	if !usePaginator {
		return nil
	}

	return &QueryPaginator{
		PageSize:  pageSize,
		PageToken: pageToken,
		iter:      nil,
	}
}

// ValidatePagination checks that the provided pagination parameters are valid. It ensures that the page
// size is greater than `MinPageSize` and that the page token, if provided, is a valid base64 URL encoded string.
func (p *QueryPaginator) Validate() error {
	if p == nil {
		return nil
	}

	if p.PageSize == 0 {
		return status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	if len(p.PageToken) > 0 {
		pToken, err := base64.URLEncoding.Strict().DecodeString(p.PageToken)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "could not parse token '%s'", p.PageToken)
		}

		p.PageToken = string(pToken)
	}

	return nil
}

func (p *QueryPaginator) BindToQuery(query *gocql.Query) *gocql.Query {
	if p == nil {
		return query.PageSize(100_000_000)
	}

	query = query.PageSize(int(p.PageSize))

	if len(p.PageToken) > 0 {
		query = query.PageState([]byte(p.PageToken))
	} else {
		query = query.PageState(nil)
	}

	return query
}

func (p *QueryPaginator) ForIter(iter *gocql.Iter) *QueryPaginator {
	if p == nil {
		return nil
	}

	p.iter = iter
	return p
}

func (p *QueryPaginator) NextPageToken() string {
	if p == nil || p.iter == nil {
		return ""
	}

	return base64.URLEncoding.Strict().EncodeToString(p.iter.PageState())
}
