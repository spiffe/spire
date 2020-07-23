package sql

import (
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

var (
	pagedNames    = []string{"", "with-token", "no-token"}
	filterByNames = []string{"", "expires-before", "selector-subset-one", "selector-subset-many", "selector-exact-one", "selector-exact-many", "attestation-type", "banned", "no-banned", "fetch-selectors"}
)

type filterBy int

const (
	noFilter filterBy = iota
	byExpiresBefore
	bySelectorSubsetOne
	bySelectorSubsetMany
	bySelectorExactOne
	bySelectorExactMany
	byAttestationType
	byBanned
	byNoBanned
	byFetchSelectors
)

func (f filterBy) String() string {
	return filterByNames[f]
}

type paged int

const (
	noPaged paged = iota
	withToken
	withNoToken
)

func (p paged) String() string {
	return pagedNames[p]
}

func TestListAttestedNodesQuery(t *testing.T) {
	for _, tt := range []struct {
		dialect     string
		paged       paged
		by          []filterBy
		supportsCTE bool
		query       string
	}{
		{
			dialect: "sqlite3",
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect: "sqlite3",
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byExpiresBefore},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND expires_at < ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{bySelectorSubsetOne},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  AS result_nodes
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{bySelectorSubsetMany},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		UNION
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  AS result_nodes
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{bySelectorExactOne},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	) 
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{bySelectorExactMany},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	) 
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byAttestationType},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND data_type = ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byBanned},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND serial_number = ''
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byNoBanned},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND serial_number <> ''
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byFetchSelectors},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byFetchSelectors},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byFetchSelectors},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{bySelectorExactMany},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{bySelectorExactMany},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byAttestationType},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND data_type = ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byAttestationType},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?		AND data_type = ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?		AND expires_at < ?
		AND data_type = ?
		AND serial_number = ''
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "sqlite3",
			by:      []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND expires_at < ?
		AND data_type = ?
		AND serial_number = ''
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes
)
`},
		{
			dialect: "postgres",
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > $1)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byExpiresBefore},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND expires_at < $1
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{bySelectorSubsetOne},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $1 AND selector_value = $2
	)  AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{bySelectorSubsetMany},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $1 AND selector_value = $2
		UNION
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $3 AND selector_value = $4
	)  AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{bySelectorExactOne},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $1 AND selector_value = $2
	)  AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{bySelectorExactMany},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $1 AND selector_value = $2
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $3 AND selector_value = $4
	)  AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byAttestationType},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND data_type = $1
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byBanned},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND serial_number = ''
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byNoBanned},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND serial_number <> ''
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byFetchSelectors},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors AS result_nodes
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byFetchSelectors},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byFetchSelectors},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > $1), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{bySelectorExactMany},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $1 AND selector_value = $2
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $3 AND selector_value = $4
	)  AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{bySelectorExactMany},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > $1), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $2 AND selector_value = $3
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $4 AND selector_value = $5
	)  AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byAttestationType},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND data_type = $1
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byAttestationType},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > $1		AND data_type = $2
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:   withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > $1		AND expires_at < $2
		AND data_type = $3
		AND serial_number = ''
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $4 AND selector_value = $5
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $6 AND selector_value = $7
	)  AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "postgres",
			by:      []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:   withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND expires_at < $1
		AND data_type = $2
		AND serial_number = ''
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $3 AND selector_value = $4
		INTERSECT
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = $5 AND selector_value = $6
	)  AS result_nodes ORDER BY id ASC LIMIT 1
)
`},
		{
			dialect: "mysql",
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true
`},
		{
			dialect: "mysql",
			paged:   withNoToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true ORDER BY N.id ASC LIMIT 1
`},
		{
			dialect: "mysql",
			paged:   withToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.id > ? ORDER BY N.id ASC LIMIT 1
`},
		{
			dialect: "mysql",
			by:      []filterBy{byExpiresBefore},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.expires_at < ?
`},
		{
			dialect: "mysql",
			by:      []filterBy{bySelectorSubsetOne},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
			INNER JOIN
			(SELECT spiffe_id FROM (
				SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?			) s_1) c_2
			USING(spiffe_id)
	)
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{bySelectorSubsetMany},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
			INNER JOIN
			(SELECT spiffe_id FROM (
				SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?
				UNION
				SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?			) s_1) c_2
			USING(spiffe_id)
	)
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{bySelectorExactOne},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_1
			USING(spiffe_id)
	)
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{bySelectorExactMany},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_1
			USING(spiffe_id)
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_2
			USING(spiffe_id)
	)
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{byAttestationType},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.data_type = ?
`},
		{
			dialect: "mysql",
			by:      []filterBy{byBanned},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.serial_number = ''
`},
		{
			dialect: "mysql",
			by:      []filterBy{byNoBanned},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.serial_number <> ''
`},
		{
			dialect: "mysql",
			by:      []filterBy{byFetchSelectors},
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
	)
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{byFetchSelectors},
			paged:   withNoToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
		) ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{byFetchSelectors},
			paged:   withToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true AND N.id > ?) c_0
		) ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{bySelectorExactMany},
			paged:   withNoToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true) c_0
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_1
			USING(spiffe_id)
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_2
			USING(spiffe_id)
		) ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{bySelectorExactMany},
			paged:   withToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true AND N.id > ?) c_0
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_1
			USING(spiffe_id)
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_2
			USING(spiffe_id)
		) ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{byAttestationType},
			paged:   withNoToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.data_type = ? ORDER BY N.id ASC LIMIT 1
`},
		{
			dialect: "mysql",
			by:      []filterBy{byAttestationType},
			paged:   withToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM attested_node_entries N
WHERE true AND N.id > ? AND N.data_type = ? ORDER BY N.id ASC LIMIT 1
`},
		{
			dialect: "mysql",
			by:      []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:   withToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true AND N.id > ? AND N.expires_at < ? AND N.data_type = ? AND N.serial_number = '') c_0
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_1
			USING(spiffe_id)
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_2
			USING(spiffe_id)
		) ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
) ORDER BY e_id, S.id
`},
		{
			dialect: "mysql",
			by:      []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:   withNoToken,
			query: `
SELECT 
	N.id as e_id,
	N.spiffe_id,
	N.data_type,
	N.serial_number,
	N.expires_at,
	N.new_serial_number,
	N.new_expires_at,
	S.type AS selector_type,
	S.value AS selector_value 
FROM attested_node_entries N
LEFT JOIN 
	node_resolver_map_entries S
ON
	N.spiffe_id = S.spiffe_id
WHERE N.id IN (
	SELECT id FROM (
		SELECT DISTINCT id FROM (
			(SELECT N.id, N.spiffe_id FROM attested_node_entries N WHERE true AND N.expires_at < ? AND N.data_type = ? AND N.serial_number = '') c_0
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_1
			USING(spiffe_id)
			INNER JOIN
			(SELECT spiffe_id FROM node_resolver_map_entries WHERE type = ? AND value = ?) c_2
			USING(spiffe_id)
		) ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
) ORDER BY e_id, S.id
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			paged:       withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
	SELECT id FROM (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			paged:       withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
	SELECT id FROM (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byExpiresBefore},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND expires_at < ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{bySelectorSubsetOne},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  AS result_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{bySelectorSubsetMany},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
		UNION
		SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?
	)  AS result_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{bySelectorExactOne},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_0

	) 
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{bySelectorExactMany},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT DISTINCT id FROM (
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_0
		INNER JOIN
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_1
		USING(id)

	) 
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byAttestationType},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND data_type = ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byBanned},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND serial_number = ''
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byNoBanned},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND serial_number <> ''
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
		SELECT id 
		FROM filtered_nodes
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byFetchSelectors},
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byFetchSelectors},
			paged:       withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT id FROM (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byFetchSelectors},
			paged:       withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT id FROM (
		SELECT DISTINCT id 
		FROM filtered_nodes_and_selectors ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{bySelectorExactMany},
			paged:       withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT id FROM (
	SELECT DISTINCT id FROM (
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_0
		INNER JOIN
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_1
		USING(id)

	)  ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{bySelectorExactMany},
			paged:       withToken, query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT id FROM (
	SELECT DISTINCT id FROM (
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_0
		INNER JOIN
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_1
		USING(id)

	)  ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byAttestationType},
			paged:       withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND data_type = ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
	SELECT id FROM (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byAttestationType},
			paged:       withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?		AND data_type = ?
)
SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	NULL AS selector_type,
	NULL AS selector_value
FROM filtered_nodes
WHERE id IN (
	SELECT id FROM (
		SELECT id 
		FROM filtered_nodes ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:       withToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND id > ?		AND expires_at < ?
		AND data_type = ?
		AND serial_number = ''
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT id FROM (
	SELECT DISTINCT id FROM (
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_0
		INNER JOIN
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_1
		USING(id)

	)  ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
		{
			dialect:     "mysql",
			supportsCTE: true,
			by:          []filterBy{byAttestationType, byBanned, bySelectorExactMany, byExpiresBefore},
			paged:       withNoToken,
			query: `
WITH filtered_nodes AS (
	SELECT * FROM attested_node_entries WHERE true
		AND expires_at < ?
		AND data_type = ?
		AND serial_number = ''
), filtered_nodes_and_selectors AS (
	    SELECT
	        filtered_nodes.*, nr.type AS selector_type, nr.value AS selector_value
	    FROM
			filtered_nodes
	    LEFT JOIN
	 	    node_resolver_map_entries nr       
	    ON
	        nr.spiffe_id=filtered_nodes.spiffe_id
	)

SELECT 
	id as e_id,
	spiffe_id,
	data_type,
	serial_number,
	expires_at,
	new_serial_number,
	new_expires_at,
	selector_type,
	selector_value 
	  
FROM filtered_nodes_and_selectors
WHERE id IN (
	SELECT id FROM (
	SELECT DISTINCT id FROM (
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_0
		INNER JOIN
		(SELECT id FROM filtered_nodes_and_selectors WHERE selector_type = ? AND selector_value = ?) c_1
		USING(id)

	)  ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
`},
	} {
		tt := tt
		name := tt.dialect + "-list-"
		if len(tt.by) > 0 {
			var byNames []string
			for _, by := range tt.by {
				byNames = append(byNames, by.String())
			}
			name += "by-" + strings.Join(byNames, "-")
		}
		if tt.paged != noPaged {
			name += "-paged-" + tt.paged.String()
		}
		if tt.supportsCTE {
			name += "-cte"
		}
		expiresBefore := time.Now().Unix()
		t.Run(name, func(t *testing.T) {
			req := new(datastore.ListAttestedNodesRequest)
			switch tt.paged {
			case withNoToken:
				req.Pagination = &datastore.Pagination{
					PageSize: 1,
				}
			case withToken:
				req.Pagination = &datastore.Pagination{
					PageSize: 1,
					Token:    "2",
				}
			}

			for _, by := range tt.by {
				switch by {
				case noFilter:
				case byExpiresBefore:
					req.ByExpiresBefore = &wrappers.Int64Value{
						Value: expiresBefore,
					}
				case bySelectorSubsetOne:
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.BySelectors_MATCH_SUBSET,
					}
				case bySelectorSubsetMany:
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.BySelectors_MATCH_SUBSET,
					}
				case bySelectorExactOne:
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.BySelectors_MATCH_EXACT,
					}
				case bySelectorExactMany:
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.BySelectors_MATCH_EXACT,
					}
				case byAttestationType:
					req.ByAttestationType = "type1"
				case byBanned:
					req.ByBanned = &wrappers.BoolValue{
						Value: true,
					}
				case byNoBanned:
					req.ByBanned = &wrappers.BoolValue{
						Value: false,
					}
				case byFetchSelectors:
					req.FetchSelectors = true
				}
			}

			query, _, err := buildListAttestedNodesQuery(tt.dialect, tt.supportsCTE, req)
			require.NoError(t, err)
			require.Equal(t, tt.query, query)
		})
	}
}
