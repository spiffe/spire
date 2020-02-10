#!/bin/bash

red=$(which tput > /dev/null && tput setaf 1 2>/dev/null || echo "")
yellow=$(which tput > /dev/null && tput setaf 3 2>/dev/null || echo "")
reset=$(which tput > /dev/null && tput sgr0 2>/dev/null || echo "")

unsupported() {
    echo "${yellow}\"build.sh $1\" is no longer necessary or supported.${reset}" 1>&2
    exit 1
}

build_protobuf() {
    make protogen
}

build_protobuf_verify() {
    make protogen-check
}

build_binaries() {
	make build
}

build_test() {
	make test
}

build_race_test() {
    make race-test
}

build_integration() {
	make integration
}

build_artifact() {
    make artificaft
}

build_all() {
    make all
}

cat << EOF 1>&2
${red}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! build.sh is deprecated and will be removed in the future !!!
!!!                                                          !!!
!!! Please invoke the Makefile directly via \`make\`           !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
${reset}
EOF

case "$1" in
	env) unsupported "$1" ;;
	setup) unsupported "$1" ;;
	utils) unsupported "$1" ;;
	protobuf) build_protobuf ;;
	protobuf_verify) build_protobuf_verify ;;
	binaries|bin) build_binaries "$2" ;;
	test) build_test ;;
	race-test) build_race_test ;;
	integration) build_integration ;;
	artifact) build_artifact ;;
	release) unsupported "$1" ;;
	clean) unsupported "$1" ;;
	distclean) unsupported "$1" ;;
	all) build_all ;;
	*) compgen -A function build_ | sed 's/build_/build.sh /' ;;
esac
