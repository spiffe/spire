package cassandra

import (
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb/pages"
)

func responsePaginationFromPager(pager *pages.QueryPaginator) *datastorev1.Pagination {
	if pager == nil {
		return nil
	}

	return &datastorev1.Pagination{
		PageSize:  pager.PageSize,
		PageToken: pager.NextPageToken(),
	}
}
