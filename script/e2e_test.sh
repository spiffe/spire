#!/bin/bash
#
# This script performs a lightweight end-to-end test of the SPIRE server and
# agent using the SQLite database. It creates a registration entry, and uses the SPIRE agent cli tool
# to fetch the minted SVID from the Workload API. This script will exit with
# code 0 if all steps are completed successfully.
#
# If a running docker system is available from the machine this test will also create a new PostgreSQL instance
# as a docker container. This database instance is then used to run the e2e test with PostgreSQL as a datastore.
#
# PLEASE NOTE: This script must be run from the project root, and will remove the
# default datastore file before beginning in order to ensure accurate results.
#

set -e

. ./script/e2e_helpers.sh

run_e2e_test() {
    rm -f .data/datastore.sqlite3
    CONFIG_LOCATION=$1

    run_test $CONFIG_LOCATION
}

run_e2e_test "conf/server/server.conf"
run_docker_test "test/configs/server/postgres.conf" "-e POSTGRES_PASSWORD=password -p 10864:5432 -d postgres"
run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:8.0.15"
