#!/bin/bash

pwd
"${ROOTDIR}/setup/x509pop/setup.sh" conf/server conf/agent

docker build --target spire-base -t spire-base .
