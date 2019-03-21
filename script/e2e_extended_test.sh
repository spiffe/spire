#!/bin/bash
#
# This script runs extended end to end tests intended to be run before
# publishing images.

set -e

. ./script/e2e_helpers.sh

run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:5.5.62"
run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:5.6.43"
run_docker_test "test/configs/server/mysql.conf" "-e MYSQL_PASSWORD=password -e MYSQL_DATABASE=mysql -e MYSQL_USER=mysql -e MYSQL_RANDOM_ROOT_PASSWORD=yes -p 6612:3306 -d mysql:5.7.25"
