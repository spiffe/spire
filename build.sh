#!/bin/bash

set -o errexit
[[ $DEBUG ]] && set -o xtrace

declare -r BINARY_DIRS="control_plane $(find plugins/*/* -maxdepth 1 -type d -not -name 'proto')"
declare -r PROTO_FILES="$(find plugins api -name '*.proto')"

declare -r GO_VERSION=${GO_VERSION:-1.8.3}
declare -r GO_URL="https://storage.googleapis.com/golang"
declare -r GO_TGZ="go${GO_VERSION}.linux-amd64.tar.gz"
declare -r PROTOBUF_VERSION=${PROTOBUF_VERSION:-3.3.0}
declare -r PROTOBUF_URL="https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}"
declare -r PROTOBUF_TGZ="protoc-${PROTOBUF_VERSION}-linux-x86_64.zip"
declare -r GLIDE_VERSION=${GLIDE_VERSION:-0.12.3}
declare -r GLIDE_URL="https://github.com/Masterminds/glide/releases/download/v${GLIDE_VERSION}"
declare -r GLIDE_TGZ="glide-v${GLIDE_VERSION}-linux-amd64.tar.gz"
declare -r PROTOC_GEN_DOCS_VERSION=${PROTOC_GEN_DOCS_VERSION:-1.0.0}
declare -r PROTOC_GEN_DOCS_URL="https://github.com/pseudomuto/protoc-gen-doc/releases/download/v${PROTOC_GEN_DOCS_VERSION}-beta/"
declare -r PROTOC_GEN_DOCS_TGZ="protoc-gen-doc-${PROTOC_GEN_DOCS_VERSION}-beta.linux-amd64.go1.8.1.tar.gz"

declare -r BUILD_DIR=${BUILD_DIR:-$PWD/.build}
declare -r BUILD_CACHE=${BUILD_CACHE:-$PWD/.cache}

[[ $CIRCLECI ]] && unset GOPATH

_exit_error() { echo "ERROR: $*" 1>&2; exit 1; }
_log_info() { echo "INFO: $*"; }

_fetch_url() {
    if [[ ! -r ${BUILD_CACHE}/${2} ]]; then
        _log_info "downloading \"${1}/${2}\""
        curl --output ${BUILD_CACHE}/${2} --location --silent ${1}/${2}
    else
        _log_info "\"${2}\" found in ${BUILD_CACHE}"
    fi
}

build_env() {
    local GOPATH GOROOT
    GOPATH="${GOPATH:-$HOME/go}"
    GOROOT="${BUILD_DIR}/golang-${GO_VERSION}"
    echo "export GOPATH=${GOPATH:-$HOME/go}"
    echo "export GOROOT=${BUILD_DIR}/golang-${GO_VERSION}"
    echo "export PATH=${GOROOT}/bin:${GOPATH}/bin:$(ls -d ${BUILD_DIR}/*/bin 2>/dev/null | tr '\n' ':')${PATH}"
}

build_setup() {
    mkdir -p ${BUILD_CACHE} ${BUILD_DIR}

    rm -rf ${GOROOT}
    mkdir -p ${GOROOT}
    _fetch_url ${GO_URL} ${GO_TGZ} 
    tar --directory ${GOROOT} --transform 's|^go/|./|' -xf ${BUILD_CACHE}/${GO_TGZ}

    rm -rf ${BUILD_DIR}/protobuf
    mkdir -p ${BUILD_DIR}/protobuf
    _fetch_url ${PROTOBUF_URL} ${PROTOBUF_TGZ}
    unzip -qod ${BUILD_DIR}/protobuf ${BUILD_CACHE}/${PROTOBUF_TGZ}

    rm -rf ${BUILD_DIR}/protoc-gen-doc
    mkdir -p ${BUILD_DIR}/protoc-gen-doc/bin
    _fetch_url ${PROTOC_GEN_DOCS_URL} ${PROTOC_GEN_DOCS_TGZ} 
    tar --directory ${BUILD_DIR}/protoc-gen-doc/bin --strip 1 -xf ${BUILD_CACHE}/${PROTOC_GEN_DOCS_TGZ}

    rm -rf ${BUILD_DIR}/glide
    mkdir -p ${BUILD_DIR}/glide/bin
    _fetch_url ${GLIDE_URL} ${GLIDE_TGZ} 
    tar --directory ${BUILD_DIR}/glide/bin --strip 1 -xf ${BUILD_CACHE}/${GLIDE_TGZ}

    go get github.com/golang/protobuf/protoc-gen-go
    go get github.com/jstemmer/go-junit-report
    go get github.com/AlekSi/gocovermerge
    go get github.com/mattn/goveralls
}

build_deps() {
    glide --home ${BUILD_CACHE} install 2>&1 | tee /tmp/glide.out
    if grep -q "Lock file may be out of date" /tmp/glide.out; then
        _exit_error "glide.lock file may be out of date"
    fi
}
    
build_protobuf() {
    local _n _d _dir _prefix="$1"

    for _n in ${PROTO_FILES}; do
        _log_info "running protoc on \"${_n}\""
        _dir="$(dirname ${_n})"
        if [[ ${_prefix} ]]; then
            _d=${_prefix}/${_dir}
            mkdir -p ${_d}
        else
            _d=${_dir}
        fi
        protoc --proto_path=${_dir} --proto_path=${GOPATH}/src --go_out=plugins=grpc:${_d} ${_n}
    done
}

build_protobuf_verify() {
    local _n _result _tmp="$(mktemp -d)"

    build_protobuf ${_tmp} >/dev/null

    for _n in $(cd $_tmp; find * -type f); do
        if ! diff ${_tmp}/${_n} ${_n} >/dev/null; then
            _log_info "proto \"${_n}\" needs regeneration"
            _result=1
        fi
    done

    if [[ -n $_result ]]; then
        _exit_error "protofub need regenerating"
    fi

    rm -rf ${_tmp}
}

build_binaries() {
    local _n _dirs="${1:-$BINARY_DIRS}"

    for _n in ${_dirs}; do
        _log_info "building in directory \"${_n}\""
        ( cd $_n; go build ${DEBUG+-v} )
    done
}

build_test() {
    test_path=$(go list ./... | grep -v -e'/vendor' -e'/proto$')
    if [[ ${CI} ]]; then
        mkdir -p .test_results/junit .test_results/coverage
        go test ${DEBUG+-v} ${test_path} | go-junit-report > .test_results/junit/report.xml
        if [[ ${COVERALLS_TOKEN} ]]; then
            gocovermerge -coverprofile=.test_results/coverage/cover.out test -covermode=count ${test_path}
            goveralls -coverprofile=.test_results/coverage/cover.out -service=circle-ci -repotoken=${COVERALLS_TOKEN}
        fi                
    else
        go test ${DEBUG+-v} ${test_path}
    fi
}

build_docs() {
    local _n _dir _doc
    for _n in ${PROTO_FILES}; do
        _dir="$(dirname ${_n})"
        _docdir="$(dirname ${_dir})"
        _log_info "creating \"${_docdir}/README.md\""
        protoc --proto_path=${_dir} --proto_path=${GOPATH}/src --doc_out=markdown,README.md:${_docdir} ${_n}
    done
}

build_clean() {
    rm -f $(find ${BINARY_DIRS} -type f -executable)
}

build_distclean() {
    build_clean
    rm -rf ${BUILD_CACHE} ${BUILD_DIR}
}

build_all() {
    build_deps
    build_protobuf
    build_docs
    build_binaries 
}

eval $(build_env)

case "$1" in
    env) build_env ;;
    setup) build_setup ;;
    deps) build_deps ;;
    protobuf) build_protobuf ;;
    protobuf_verify) build_protobuf_verify ;;
    binaries|bin) build_binaries $2 ;;
    test) build_test ;;
    docs) build_docs ;;
    clean) build_clean ;;
    distclean) build_distclean ;;
    all) build_all ;;
    *) compgen -A function build_ | sed 's/build_/build.sh /' ;;
esac

