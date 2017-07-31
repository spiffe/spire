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

declare -r BUILD_DIR=${BUILD_DIR:-$PWD/.build}
declare -r BUILD_CACHE=${BUILD_CACHE:-$PWD/.cache}

[[ $CIRCLECI ]] && unset GOPATH
declare -xr GOPATH=${GOPATH:-$HOME/go}
declare -xr GOROOT=${BUILD_DIR}/golang
declare -xr PATH=${GOROOT}/bin:${GOPATH}/bin:${BUILD_DIR}/protobuf/bin:${BUILD_DIR}/glide/bin:${PATH}


_fetch_url() {
    if [[ ! -r ${BUILD_CACHE}/${2} ]]; then
        _log_info "downloading \"${1}/${2}\""
        curl --output ${BUILD_CACHE}/${2} --location --silent ${1}/${2}
    else
        _log_info "\"${2}\" found in ${BUILD_CACHE}"
    fi
}

_exit_error() { echo "ERROR: $*" 1>2; exit 1; }
_log_info() { echo "INFO: $*"; }

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

    rm -rf ${BUILD_DIR}/glide
    _fetch_url ${GLIDE_URL} ${GLIDE_TGZ} 
    tar --directory ${BUILD_DIR} --transform 's|^linux-amd64|glide/bin|' -xf ${BUILD_CACHE}/${GLIDE_TGZ}

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
    local _n _dir
    for _n in ${PROTO_FILES}; do
        _log_info "running protoc on \"${_n}\""
        _dir="$(dirname ${_n})"
        protoc --proto_path=${_dir} --proto_path=${GOPATH}/src --go_out=plugins=grpc:${_dir} ${_n}
    done
}

build_binaries() {
    local _n _dirs="$@"
    for _n in ${_dirs}; do
        _log_info "building in directory \"${_n}\""
        ( cd $_n; go build ${DEBUG+-v} )
    done
}

build_test() {
    test_path=$(go list ./... | grep -v -e'/vendor' -e'/proto$')
    if [[ ${CI} ]]; then
        mkdir -p .test_results/junit .test_results/coverage
        go test -v ${test_path} | go-junit-report > .test_results/junit/report.xml
        if [[ ${COVERALLS_TOKEN} ]]; then
            gocovermerge -coverprofile=.test_results/coverage/cover.out test -covermode=count ${test_path}
            goveralls -coverprofile=.test_results/coverage/cover.out -service=circle-ci -repotoken=${COVERALLS_TOKEN}
        fi                
    else
        go test -v ${test_path}
    fi
}

build_clean() {
    rm -f ${BINARIES} 
}

build_distclean() {
    rm -rf ${BUILD_CACHE} ${BUILD_DIR}
}

case $1 in
    setup) build_setup ;;
    deps) build_deps ;;
    protobuf) build_protobuf ;;
    binaries|bin) build_binaries ${2:-$BINARY_DIRS} ;;
    test) build_test ;;
    clean) build_clean ;;
    distclean) build_clean; build_distclean ;;
    all) build_deps; build_binaries ${2:-$BINARY_DIRS} ;;
esac

