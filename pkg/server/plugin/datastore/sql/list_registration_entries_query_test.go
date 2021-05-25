package sql

import (
	"strings"
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestListRegistrationEntriesQuery(t *testing.T) {
	testCases := []struct {
		dialect     string
		paged       string
		by          []string
		supportsCTE bool
		query       string
	}{
		{
			dialect: "sqlite3",
			query: `
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-subset-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-exact-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		) s_1
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			paged:   "no-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0 WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			query: `
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = $1 AND spiffe_id = $2
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-subset-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $3 AND value = $4
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-exact-one"},
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $1 AND value = $2
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $3 AND value = $4
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = $4 AND value = $5
		) s_1
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $4 AND value = $5
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			paged:   "no-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE id > $1 ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1 AND id > $2 ORDER BY id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1
		INTERSECT
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = $2 AND value = $3
	) s_0 WHERE e_id > $4 ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "spiffe-id"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"selector-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		) s_1) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "selector-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_2
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			paged:   "no-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id"},
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id", "selector-exact-one"},
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			supportsCTE: true,
			query: `
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "spiffe-id"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT id AS e_id FROM registered_entries WHERE parent_id = ? AND spiffe_id = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		UNION
		SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"selector-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT e_id FROM (
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
			UNION
			SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?
		) s_1) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "selector-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
		USING(e_id)
		INNER JOIN
		(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_2
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			paged:       "no-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id"},
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ? AND id > ? ORDER BY id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id", "selector-exact-one"},
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT registered_entry_id AS e_id FROM selectors WHERE type = ? AND value = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"parent-id", "federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "sqlite3",
			by:      []string{"spiffe-id", "federates-with-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
	) s_0 WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN ($2) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1, $2) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN ($3, $4) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN ($2) THEN B.trust_domain ELSE NULL END) = $3
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN ($1, $2) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN ($3, $4) THEN B.trust_domain ELSE NULL END) = $5
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-subset-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN ($3) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-subset-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2, $3) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN ($4, $5) THEN B.trust_domain ELSE NULL END) > 0
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-exact-one"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN ($3) THEN B.trust_domain ELSE NULL END) = $4
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"parent-id", "federates-with-exact-many"},
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE parent_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2, $3) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN ($4, $5) THEN B.trust_domain ELSE NULL END) = $6
	) s_0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "postgres",
			by:      []string{"spiffe-id", "federates-with-exact-one"},
			paged:   "with-token",
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT id AS e_id FROM registered_entries WHERE spiffe_id = $1
		INTERSECT
		SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN ($2) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN ($3) THEN B.trust_domain ELSE NULL END) = $4
	) s_0 WHERE e_id > $5 ORDER BY e_id ASC LIMIT 1
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL ::integer AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL ::integer AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"federates-with-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-subset-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-subset-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-exact-one"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"parent-id", "federates-with-exact-many"},
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect: "mysql",
			by:      []string{"spiffe-id", "federates-with-exact-one"},
			paged:   "with-token",
			query: `
SELECT
	E.id AS e_id,
	E.entry_id AS entry_id,
	E.spiffe_id,
	E.parent_id,
	E.ttl AS reg_ttl,
	E.admin,
	E.downstream,
	E.expiry,
	S.id AS selector_id,
	S.type AS selector_type,
	S.value AS selector_value,
	B.trust_domain,
	D.id AS dns_name_id,
	D.value AS dns_name,
	E.revision_number
FROM
	registered_entries E
LEFT JOIN
	(SELECT 1 AS joinItem UNION SELECT 2 UNION SELECT 3) AS joinItems ON TRUE
LEFT JOIN
	selectors S ON joinItem=1 AND E.id=S.registered_entry_id
LEFT JOIN
	dns_names D ON joinItem=2 AND E.id=D.registered_entry_id
LEFT JOIN
	(federated_registration_entries F INNER JOIN bundles B ON F.bundle_id=B.id) ON joinItem=3 AND E.id=F.registered_entry_id
WHERE E.id IN (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT E.id AS e_id
			FROM registered_entries E
			INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
			INNER JOIN bundles B ON B.id = FE.bundle_id
			GROUP BY E.id
			HAVING
				COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
				COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"federates-with-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT E.id AS e_id
	FROM registered_entries E
	INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
	INNER JOIN bundles B ON B.id = FE.bundle_id
	GROUP BY E.id
	HAVING
		COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
		COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-subset-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-subset-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) > 0) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-exact-one"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"parent-id", "federates-with-exact-many"},
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT DISTINCT e_id FROM (
		(SELECT id AS e_id FROM registered_entries WHERE parent_id = ?) c_0
		INNER JOIN
		(SELECT E.id AS e_id
		FROM registered_entries E
		INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
		INNER JOIN bundles B ON B.id = FE.bundle_id
		GROUP BY E.id
		HAVING
			COUNT(CASE WHEN B.trust_domain NOT IN (?, ?) THEN B.trust_domain ELSE NULL END) = 0 AND
			COUNT(DISTINCT CASE WHEN B.trust_domain IN (?, ?) THEN B.trust_domain ELSE NULL END) = ?) c_1
		USING(e_id)
	)
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
		{
			dialect:     "mysql",
			by:          []string{"spiffe-id", "federates-with-exact-one"},
			paged:       "with-token",
			supportsCTE: true,
			query: `
WITH listing AS (
	SELECT e_id FROM (
		SELECT DISTINCT e_id FROM (
			(SELECT id AS e_id FROM registered_entries WHERE spiffe_id = ?) c_0
			INNER JOIN
			(SELECT E.id AS e_id
			FROM registered_entries E
			INNER JOIN federated_registration_entries FE ON FE.registered_entry_id = E.id
			INNER JOIN bundles B ON B.id = FE.bundle_id
			GROUP BY E.id
			HAVING
				COUNT(CASE WHEN B.trust_domain NOT IN (?) THEN B.trust_domain ELSE NULL END) = 0 AND
				COUNT(DISTINCT CASE WHEN B.trust_domain IN (?) THEN B.trust_domain ELSE NULL END) = ?) c_1
			USING(e_id)
		) WHERE e_id > ? ORDER BY e_id ASC LIMIT 1
	) workaround_for_mysql_subquery_limit
)
SELECT
	id AS e_id,
	entry_id,
	spiffe_id,
	parent_id,
	ttl AS reg_ttl,
	admin,
	downstream,
	expiry,
	NULL AS selector_id,
	NULL AS selector_type,
	NULL AS selector_value,
	NULL AS trust_domain,
	NULL AS dns_name_id,
	NULL AS dns_name,
	revision_number
FROM
	registered_entries
WHERE id IN (SELECT e_id FROM listing)

UNION

SELECT
	F.registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, B.trust_domain, NULL, NULL, NULL
FROM
	bundles B
INNER JOIN
	federated_registration_entries F
ON
	B.id = F.bundle_id
WHERE
	F.registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, value, NULL
FROM
	dns_names
WHERE registered_entry_id IN (SELECT e_id FROM listing)

UNION

SELECT
	registered_entry_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id, type, value, NULL, NULL, NULL, NULL
FROM
	selectors
WHERE registered_entry_id IN (SELECT e_id FROM listing)

ORDER BY e_id, selector_id, dns_name_id
;`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		name := testCase.dialect + "-list-"
		if len(testCase.by) == 0 {
			name += "all"
		} else {
			name += "by-" + strings.Join(testCase.by, "-")
		}
		if testCase.paged != "" {
			name += "-paged-" + testCase.paged
		}
		if testCase.supportsCTE {
			name += "-cte"
		}
		t.Run(name, func(t *testing.T) {
			req := new(datastore.ListRegistrationEntriesRequest)
			switch testCase.paged {
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
				require.FailNow(t, "unsupported page case: %q", testCase.paged)
			}

			for _, by := range testCase.by {
				switch by {
				case "parent-id":
					req.ByParentID = "spiffe://parent"
				case "spiffe-id":
					req.BySpiffeID = "spiffe://id"
				case "selector-subset-one":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.Subset,
					}
				case "selector-subset-many":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.Subset,
					}
				case "selector-exact-one":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}},
						Match:     datastore.Exact,
					}
				case "selector-exact-many":
					req.BySelectors = &datastore.BySelectors{
						Selectors: []*common.Selector{{Type: "a", Value: "1"}, {Type: "b", Value: "2"}},
						Match:     datastore.Exact,
					}
				case "federates-with-subset-one":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test"},
						Match:        datastore.Subset,
					}
				case "federates-with-subset-many":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test", "spiffe://federates2.test"},
						Match:        datastore.Subset,
					}
				case "federates-with-exact-one":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test"},
						Match:        datastore.Exact,
					}
				case "federates-with-exact-many":
					req.ByFederatesWith = &datastore.ByFederatesWith{
						TrustDomains: []string{"spiffe://federates1.test", "spiffe://federates2.test"},
						Match:        datastore.Exact,
					}
				default:
					require.FailNow(t, "unsupported by case: %q", by)
				}
			}

			query, _, err := buildListRegistrationEntriesQuery(testCase.dialect, testCase.supportsCTE, req)
			require.NoError(t, err)
			require.Equal(t, testCase.query, query)
		})
	}
}
