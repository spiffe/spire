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

func TestListAttestedNodesQuery(t *testing.T) {
	for _, tt := range []struct {
		dialect     string
		paged       string
		by          []string
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
			paged:   "no-token",
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
			paged:   "with-token",
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
			by:      []string{"expires-before"},
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
			by:      []string{"selector-subset-one"},
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
			by:      []string{"selector-subset-many"},
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
			by:      []string{"selector-exact-one"},
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
			by:      []string{"selector-exact-many"},
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
			by:      []string{"attestation-type"},
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
			by:      []string{"banned-true"},
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
			by:      []string{"banned-false"},
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
			by:      []string{"fetch-selectors"},
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
			by:      []string{"fetch-selectors"},
			paged:   "no-token",
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
			by:      []string{"fetch-selectors"},
			paged:   "with-token",
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
			by:      []string{"selector-exact-many"},
			paged:   "no-token",
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
			by:      []string{"selector-exact-many"},
			paged:   "with-token", query: `
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
			by:      []string{"attestation-type"},
			paged:   "no-token",
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
			by:      []string{"attestation-type"},
			paged:   "with-token",
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
			by:      []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:   "with-token",
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
			by:      []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:   "no-token",
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
			paged:   "no-token",
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
			paged:   "with-token",
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
			by:      []string{"expires-before"},
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
			by:      []string{"selector-subset-one"},
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
			by:      []string{"selector-subset-many"},
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
			by:      []string{"selector-exact-one"},
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
			by:      []string{"selector-exact-many"},
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
			by:      []string{"attestation-type"},
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
			by:      []string{"banned-true"},
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
			by:      []string{"banned-false"},
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
			by:      []string{"fetch-selectors"},
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
			by:      []string{"fetch-selectors"},
			paged:   "no-token",
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
			by:      []string{"fetch-selectors"},
			paged:   "with-token",
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
			by:      []string{"selector-exact-many"},
			paged:   "no-token",
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
			by:      []string{"selector-exact-many"},
			paged:   "with-token", query: `
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
			by:      []string{"attestation-type"},
			paged:   "no-token",
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
			by:      []string{"attestation-type"},
			paged:   "with-token",
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
			by:      []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:   "with-token",
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
			by:      []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:   "no-token",
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
			paged:   "no-token",
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
			paged:   "with-token",
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
			by:      []string{"expires-before"},
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
			by:      []string{"selector-subset-one"},
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
			by:      []string{"selector-subset-many"},
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
			by:      []string{"selector-exact-one"},
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
			by:      []string{"selector-exact-many"},
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
			by:      []string{"attestation-type"},
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
			by:      []string{"banned-true"},
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
			by:      []string{"banned-false"},
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
			by:      []string{"fetch-selectors"},
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
			by:      []string{"fetch-selectors"},
			paged:   "no-token",
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
			by:      []string{"fetch-selectors"},
			paged:   "with-token",
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
			by:      []string{"selector-exact-many"},
			paged:   "no-token",
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
			by:      []string{"selector-exact-many"},
			paged:   "with-token", query: `
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
			by:      []string{"attestation-type"},
			paged:   "no-token",
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
			by:      []string{"attestation-type"},
			paged:   "with-token",
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
			by:      []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:   "with-token",
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
			by:      []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:   "no-token",
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
			paged:       "no-token",
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
			paged:       "with-token",
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
			by:          []string{"expires-before"},
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
			by:          []string{"selector-subset-one"},
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
			by:          []string{"selector-subset-many"},
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
			by:          []string{"selector-exact-one"},
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
			by:          []string{"selector-exact-many"},
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
			by:          []string{"attestation-type"},
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
			by:          []string{"banned-true"},
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
			by:          []string{"banned-false"},
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
			by:          []string{"fetch-selectors"},
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
			by:          []string{"fetch-selectors"},
			paged:       "no-token",
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
			by:          []string{"fetch-selectors"},
			paged:       "with-token",
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
			by:          []string{"selector-exact-many"},
			paged:       "no-token",
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
			by:          []string{"selector-exact-many"},
			paged:       "with-token", query: `
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
			by:          []string{"attestation-type"},
			paged:       "no-token",
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
			by:          []string{"attestation-type"},
			paged:       "with-token",
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
			by:          []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:       "with-token",
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
			by:          []string{"attestation-type", "banned-true", "selector-exact-many", "expires-before"},
			paged:       "no-token",
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
		if len(tt.by) == 0 {

		} else {
			name += "by-" + strings.Join(tt.by, "-")
		}
		if tt.paged != "" {
			name += "-paged-" + tt.paged
		}
		if tt.supportsCTE {
			name += "-cte"
		}
		expiresBefore := time.Now().Unix()
		t.Run(name, func(t *testing.T) {
			req := new(datastore.ListAttestedNodesRequest)
			switch tt.paged {
			case "":
			case "no-token":
				req.Pagination = &datastore.Pagination{
					PageSize: 1,
				}
			case "with-token":
				req.Pagination = &datastore.Pagination{
					PageSize: 1,
					Token:    "2",
				}
			default:
				require.FailNow(t, "unsupported page case: %q", tt.paged)
			}

			for _, by := range tt.by {
				switch by {
				case "expires-before":
					req.ByExpiresBefore = &wrappers.Int64Value{
						Value: expiresBefore,
					}
				case "selector-subset-one":
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.BySelectors_MATCH_SUBSET,
					}
				case "selector-subset-many":
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.BySelectors_MATCH_SUBSET,
					}
				case "selector-exact-one":
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.BySelectors_MATCH_EXACT,
					}
				case "selector-exact-many":
					req.BySelectorMatch = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.BySelectors_MATCH_EXACT,
					}
				case "attestation-type":
					req.ByAttestationType = "type1"
				case "banned-true":
					req.ByBanned = &wrappers.BoolValue{
						Value: true,
					}
				case "banned-false":
					req.ByBanned = &wrappers.BoolValue{
						Value: false,
					}
				case "fetch-selectors":
					req.FetchSelectors = true

				default:
					require.FailNow(t, "unsupported by case: %q", by)
				}
			}

			query, _, err := buildListAttestedNodesQuery(tt.dialect, tt.supportsCTE, req)
			require.NoError(t, err)
			require.Equal(t, tt.query, query)
		})
	}
}
