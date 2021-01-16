#!/bin/bash
echo "host replication all 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
CREATE USER $PG_REP_USER  WITH REPLICATION ENCRYPTED PASSWORD '$PG_REP_PASSWORD';
EOSQL

cat >> ${PGDATA}/postgresql.conf <<EOF
wal_level = hot_standby
max_wal_senders = 8
wal_keep_segments = 8
hot_standby = on
EOF
