#!/bin/bash

set -o errexit
[[ -n $DEBUG ]] && set -o xtrace

declare -r BINARY_DIRS="$(find cmd/* plugin/*/* -maxdepth 0 -type d)"
declare -r PROTO_FILES="$(find pkg -name '*.proto')"

case $(uname) in
    Darwin) declare -r OS1="darwin"
			declare -r OS2="osx"
			;;
	Linux)  declare -r OS1="linux"
			declare -r OS2="linux"
			;;
esac

case $(uname -m) in
	x86_64) declare -r ARCH1="x86_64"
			declare -r ARCH2="amd64"
			;;
esac

declare -r BUILD_DIR=${BUILD_DIR:-$PWD/.build-${OS1}-${ARCH1}}
declare -r BUILD_CACHE=${BUILD_CACHE:-$PWD/.cache}

# versioned packages that we need
declare -r GO_VERSION=${GO_VERSION:-1.8.3}
declare -r GO_URL="https://storage.googleapis.com/golang"
declare -r GO_TGZ="go${GO_VERSION}.${OS1}-${ARCH2}.tar.gz"
declare -r PROTOBUF_VERSION=${PROTOBUF_VERSION:-3.3.0}
declare -r PROTOBUF_URL="https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}"
declare -r PROTOBUF_TGZ="protoc-${PROTOBUF_VERSION}-${OS2}-${ARCH1}.zip"
declare -r GLIDE_VERSION=${GLIDE_VERSION:-0.12.3}
declare -r GLIDE_URL="https://github.com/Masterminds/glide/releases/download/v${GLIDE_VERSION}"
declare -r GLIDE_TGZ="glide-v${GLIDE_VERSION}-${OS1}-${ARCH2}.tar.gz"
declare -r PROTOC_GEN_DOCS_VERSION=${PROTOC_GEN_DOCS_VERSION:-1.0.0-beta}
declare -r PROTOC_GEN_DOCS_URL="https://github.com/pseudomuto/protoc-gen-doc/releases/download/v${PROTOC_GEN_DOCS_VERSION}"
declare -r PROTOC_GEN_DOCS_TGZ="protoc-gen-doc-${PROTOC_GEN_DOCS_VERSION}.${OS1}-${ARCH2}.go1.8.1.tar.gz"

[[ -n $CIRCLECI ]] && unset GOPATH

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
    local _gp _gr

    _gp="${GOPATH:-$HOME/go}"
    _gr="${BUILD_DIR}/golang-${GO_VERSION}"
    echo "export GOPATH=${_gp}"
    echo "export GOROOT=${BUILD_DIR}/golang-${GO_VERSION}"
    echo "export PATH=${_gr}/bin:${_gp}/bin:$(ls -d ${BUILD_DIR}/*/bin 2>/dev/null | tr '\n' ':')${PATH}"
}

build_setup() {
    eval $(build_env)

    mkdir -p ${BUILD_CACHE} ${BUILD_DIR}

    rm -rf ${GOROOT}
    mkdir -p ${GOROOT}
    _fetch_url ${GO_URL} ${GO_TGZ}
    tar --directory ${GOROOT} --strip 1 -xf ${BUILD_CACHE}/${GO_TGZ}

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

	# tools the build needs, version is not important
    go get github.com/golang/protobuf/protoc-gen-go
    go get github.com/jstemmer/go-junit-report
    go get github.com/AlekSi/gocoverutil
    go get github.com/mattn/goveralls
    go get github.com/jteeuwen/go-bindata/...
    go get github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
    go get github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
}

build_deps() {
    eval $(build_env)

    glide --home ${BUILD_CACHE} install 2>&1 | tee /tmp/glide.out
    if grep -q "Lock file may be out of date" /tmp/glide.out; then
        _exit_error "glide.lock file may be out of date"
    fi
}

build_protobuf() {
    local _n _d _dir _prefix="$1"
    eval $(build_env)

    for _n in ${PROTO_FILES}; do
        _dir="$(dirname ${_n})"
        if [[ -n ${_prefix} ]]; then
            _d=${_prefix}/${_dir}
            mkdir -p ${_d}
        else
            _d=${_dir}
        fi
        _log_info "creating \"${_n%.proto}.pb.go\""
        protoc --proto_path=${_dir} --proto_path=${GOPATH}/src \
            --proto_path=${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
            --go_out=plugins=grpc:${_d} ${_n}
        _log_info "creating \"${_d}/README_pb.md\""
        protoc --proto_path=${_dir} --proto_path=${GOPATH}/src \
            --proto_path=${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
            --doc_out=markdown,README_pb.md:${_d} ${_n}
        if grep -q 'option (google.api.http)' ${_n}; then
            _log_info "creating http gateway \"${_n%.proto}.pb.gw.go\""
            protoc --proto_path=${_dir} --proto_path=${GOPATH}/src \
                --proto_path=${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
                --grpc-gateway_out=logtostderr=true:${_d} ${_n}
        fi
    done
}

build_protobuf_verify() {
    local _n _result _tmp="$(mktemp -d)"
    eval $(build_env)

    build_protobuf ${_tmp} >/dev/null

    for _n in $(cd $_tmp; find * -type f); do
        if ! diff ${_tmp}/${_n} ${_n} >/dev/null; then
            _log_info "\"${_n}\" needs regeneration"
            _result=1
        fi
    done

    if [[ -n $_result ]]; then
        _exit_error "protobuf need regenerating"
    fi

    rm -rf ${_tmp}
}

build_binaries() {
    local _n _dirs="${1:-$BINARY_DIRS}"
    eval $(build_env)

    for _n in ${_dirs}; do
        _log_info "building in directory \"${_n}\""
        ( cd $_n; go build ${DEBUG+-v} -i )
    done
}

build_test() {
    local _test_path _result
    eval $(build_env)

    _test_path=$(go list ./... | grep -v -e'/vendor')
    if [[ -n ${CI} ]]; then
        mkdir -p test_results
        go test ${DEBUG+-v} -race ${_test_path} | tee test_results/report.raw
        cat test_results/report.raw | go-junit-report > test_results/report.xml
        if [[ -n ${COVERALLS_TOKEN} && ${TRAVIS_EVENT_TYPE} = cron ]]; then
            gocoverutil -coverprofile=test_results/cover.out test -covermode=count ${_test_path}
            goveralls -coverprofile=test_results/cover.out -service=circle-ci -repotoken=${COVERALLS_TOKEN}
        fi
    else
        go test ${DEBUG+-v} -race ${_test_path}
    fi
}

build_artifact() {
	local _hash _libc _artifact _binaries _n _tmp

	_binaries="$(find $BINARY_DIRS -executable -a -type f)"

	mkdir -p artifacts

	# handle the case that we're building for alpine
	if [[ $OS1 == linux ]]; then
		case $(ldd --version 2>&1) in
			*GLIB*) _libc="-glibc" ;;
			*muslr*) _libc="-musl" ;;
			*) _libc="-unknown" ;;
		esac
	fi
	_hash="$(git log -n1 --pretty=format:%h)"
    _artifact="spire-${_hash}-${_os}-${ARCH1}${_libc}.tgz"

    _log_info "creating artifact \"${_artifact}\""

	_tmp=".tmp/spire"
	rm -rf $_tmp
	mkdir -p $_tmp

	# we munge the file structure a bit here
	for _n in $_binaries; do
		if [[ $_n == *cmd/* ]]; then
			cp $_n $_tmp
		elif [[ $_n == *plugin/* ]]; then
			mkdir -p ${_tmp}/$(dirname $(dirname $_n))
			cp -r $_n ${_tmp}/$(dirname $_n)
		fi
	done

    tar --directory .tmp -cvzf artifacts/${_artifact} .
}

build_clean() {
    rm -f $(find ${BINARY_DIRS} -type f -perm '-u+x')
}

build_distclean() {
    build_clean
    rm -rf ${BUILD_CACHE} ${BUILD_DIR}
}

build_all() {
    build_setup
    build_deps
    build_binaries
    build_test
}


case "$1" in
    env) build_env ;;
    setup) build_setup ;;
    deps) build_deps ;;
    protobuf) build_protobuf ;;
    protobuf_verify) build_protobuf_verify ;;
    binaries|bin) build_binaries $2 ;;
    test) build_test ;;
    artifact) build_artifact ;;
    clean) build_clean ;;
    distclean) build_distclean ;;
    all) build_all ;;
    *) compgen -A function build_ | sed 's/build_/build.sh /' ;;
esac

