#!/bin/bash

set -ex

PROTOBUF_VERSION=${PROTOBUF_VERSION:-3.3.0}
GO_VERSION=${GO_VERSION:-1.8.3}
GLIDE_VERSION=${GLIDE_VERSION:-0.12.3}
BUILD_DIR=${BUILD_DIR:-$PWD/.build}
BUILD_CACHE=${BUILD_CACHE:-$PWD/.cache}

export GOPATH=${HOME}/go
export GOROOT=${BUILD_DIR}/golang
export PATH=${GOROOT}/bin:${GOPATH}/bin:${BUILD_DIR}/protobuf/bin:${BUILD_DIR}/glide/bin:${PATH}

_fetch_url() {
    if [[ ! -r ${BUILD_CACHE}/${2} ]]; then
        curl --output ${BUILD_CACHE}/${2} --location --silent ${1}/${2}
    fi
}

build_setup() {
    go_url="https://storage.googleapis.com/golang"
    go_tgz="go${GO_VERSION}.linux-amd64.tar.gz"
    pb_url="https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}"
    pb_tgz="protoc-${PROTOBUF_VERSION}-linux-x86_64.zip"
    glide_url="https://github.com/Masterminds/glide/releases/download/v${GLIDE_VERSION}"
    glide_tgz="glide-v${GLIDE_VERSION}-linux-amd64.tar.gz"

    mkdir -p ${BUILD_CACHE} ${BUILD_DIR}
    _fetch_url ${pb_url} ${pb_tgz}
    _fetch_url ${go_url} ${go_tgz} 
    _fetch_url ${glide_url} ${glide_tgz} 
      
    rm -rf ${GOROOT}
    mkdir -p ${GOROOT}
    tar --directory ${GOROOT} --transform 's|^go||' -xf ${BUILD_CACHE}/${go_tgz}

    rm -rf ${BUILD_DIR}/protobuf
    mkdir -p ${BUILD_DIR}/protobuf
    unzip -qod ${BUILD_DIR}/protobuf ${BUILD_CACHE}/${pb_tgz}

    rm -rf ${BUILD_DIR}/glide
    tar --directory ${BUILD_DIR} --transform 's|^linux-amd64|glide/bin|' -xf ${BUILD_CACHE}/${glide_tgz}

    go get github.com/golang/protobuf/protoc-gen-go
    go get github.com/jstemmer/go-junit-report
    go get github.com/AlekSi/gocovermerge
    go get github.com/mattn/goveralls
}

build_deps() {
	glide --home .${BUILD_CACHE} install 2>&1 | tee /tmp/glide.out
	if grep -q WARN /tmp/glide.out; then
        echo "[ERROR] glide.lock file may be out of date"
        return 1
    fi
}

	
build_protobuf() {
    local _n
    for _n in $(find plugins api -name '*.proto'); do
        protoc ${_n} --go_out=plugins=grpc:.
    done
}

build_binaries() {
    local _n
    for _n in control_plane $(find plugins/*/* -maxdepth 1 -type d -not -name 'proto'); do
        ( cd $_n; go build )
    done
}

build_test() {
	test_path=$(go list ./... | egrep -v '(/vendor|/proto$$)')
    if [[ $CI ]]; then
        mkdir -p .test_results/junit .test_results/coverage
        go test -v ${test_path} | go-junit-report > .test_results/junit/report.xml
        if [[ $COVERALLS_TOKEN ]]; then
            gocovermerge -coverprofile=.test_results/coverage/cover.out test -covermode=count ${test_path}
            goveralls -coverprofile=.test_results/coverage/cover.out -service=circle-ci -repotoken=${COVERALLS_TOKEN}
        fi                
    else
        go test -v ${test_path}
    fi
}

build_clean() {
	rm -f ${BINARIES} ${PROTOBUF_GO}
}

build_distclean() {
	rm -rf ${BUILD_CACHE} ${BUILD_DIR}
}

case $1 in
    setup) build_setup ;;
    deps) build_deps ;;
    protobuf) build_protobuf ;;
    binaries|bin) build_binaries ;;
    test) build_test ;;
    clean) build_clean ;;
    distclean) build_clean; build_distclean ;;
    all) build_deps; build_binaries ;;
esac

