#!/bin/bash

set -o errexit
[[ -n $DEBUG ]] && set -o xtrace

declare -r ARTIFACT_DIRS="$(find cmd/* functional/* -maxdepth 0 -type d 2>/dev/null)"
declare -r RELEASE_DIRS="$(find cmd/* -maxdepth 0 -type d 2>/dev/null)"
declare -r SOURCE_PKGS="$(go list ./cmd/... ./pkg/... 2>/dev/null)"
declare -r RELEASE_FILES="LICENSE README.md conf"
declare -r PROTO_FILES="$(find proto -name '*.proto' 2>/dev/null)"

case $(uname) in
	Darwin) declare -r OS1="darwin"
			declare -r OS2="osx"
			;;
	Linux)	declare -r OS1="linux"
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

# versioned binaries that we need for builds

declare -r GO_VERSION=${GO_VERSION:-1.10}
declare -r GO_URL="https://storage.googleapis.com/golang"
declare -r GO_TGZ="go${GO_VERSION}.${OS1}-${ARCH2}.tar.gz"
declare -r PROTOBUF_VERSION=${PROTOBUF_VERSION:-3.3.0}
declare -r PROTOBUF_URL="https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}"
declare -r PROTOBUF_TGZ="protoc-${PROTOBUF_VERSION}-${OS2}-${ARCH1}.zip"
declare -r GLIDE_VERSION=${GLIDE_VERSION:-0.12.3}
declare -r GLIDE_URL="https://github.com/Masterminds/glide/releases/download/v${GLIDE_VERSION}"
declare -r GLIDE_TGZ="glide-v${GLIDE_VERSION}-${OS1}-${ARCH2}.tar.gz"
declare -r PROTOC_GEN_DOCS_VERSION=${PROTOC_GEN_DOCS_VERSION:-1.0.0}
declare -r PROTOC_GEN_DOCS_URL="https://github.com/pseudomuto/protoc-gen-doc/releases/download/v${PROTOC_GEN_DOCS_VERSION}"
declare -r PROTOC_GEN_DOCS_TGZ="protoc-gen-doc-${PROTOC_GEN_DOCS_VERSION}.${OS1}-${ARCH2}.go1.9.tar.gz"

[[ -n $TRAVIS ]] && unset GOPATH GOROOT

_exit_error() { echo "ERROR: $*" 1>&2; exit 1; }
_log_info() { echo "INFO: $*"; }

_fetch_url() {
	mkdir -p ${BUILD_CACHE}
	if [[ ! -r ${BUILD_CACHE}/${2} ]]; then
		_log_info "downloading \"${1}/${2}\""
		curl --output ${BUILD_CACHE}/${2} --location --silent ${1}/${2}
	else
		_log_info "\"${2}\" found in ${BUILD_CACHE}"
	fi
}

## print export commands to set up the environment
## to use our private set of tools
build_env() {
	local _gp _gr

	_gp="${GOPATH:-$HOME/gopath}"
	_gr="${GOROOT:-$BUILD_DIR}"
	echo "export GOPATH=${_gp}"
	echo "export GOROOT=${_gr}"
	echo "export PATH=$(ls -d ${BUILD_DIR}/*/bin 2>/dev/null | tr '\n' ':'):${_gr}/bin:${_gp}/bin:${PATH}"
}

## fetch first-party versions of binaries we can not 'go get'
build_setup() {
	eval $(build_env)

	rm -rf ${BUILD_DIR}
	mkdir -p ${BUILD_DIR}

	_fetch_url ${GO_URL} ${GO_TGZ}
	tar --directory ${BUILD_DIR} --strip 1 -xf ${BUILD_CACHE}/${GO_TGZ}

	_fetch_url ${GLIDE_URL} ${GLIDE_TGZ}
	tar --directory ${BUILD_DIR}/bin --strip 1 -xf ${BUILD_CACHE}/${GLIDE_TGZ}

	_fetch_url ${PROTOC_GEN_DOCS_URL} ${PROTOC_GEN_DOCS_TGZ}
	tar --directory ${BUILD_DIR}/bin --strip 1 -xf ${BUILD_CACHE}/${PROTOC_GEN_DOCS_TGZ}

	_fetch_url ${PROTOBUF_URL} ${PROTOBUF_TGZ}
	unzip -qod ${BUILD_DIR} ${BUILD_CACHE}/${PROTOBUF_TGZ}
}

## go-get extra utils needed for CI builds
build_utils() {
	eval $(build_env)

	make utils
	go get github.com/AlekSi/gocoverutil
	go get github.com/mattn/goveralls
}

## Fetch all vendored dependancies and check if the lock file
## is up-to-date
build_vendor() {
	eval $(build_env)

	make vendor 2>&1 | tee /tmp/glide.out
	if grep -q "Lock file may be out of date" /tmp/glide.out; then
		_exit_error "glide.lock file may be out of date"
	fi
}

## Rebuild all .proto files, generated README, and generated gRPC/REST interfaces
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
		# only build gateway code if necessary
		if grep -q 'option (google.api.http)' ${_n}; then
			_log_info "creating http gateway \"${_n%.proto}.pb.gw.go\""
			protoc --proto_path=${_dir} --proto_path=${GOPATH}/src \
				--proto_path=${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
				--grpc-gateway_out=logtostderr=true:${_d} ${_n}
		fi
	done
}

## Create a private copy of generated code and compare it to
## what's checked in. Fail if there's a difference
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
	eval $(build_env)
	make build
}

## Run coverate tests and send to coveralls if this CI build
## has been called by cron.
build_test() {
	eval $(build_env)

	if [[ -n ${COVERALLS_TOKEN} ]]; then
		_log_info "running coverage tests"
		rm -rf test_results
		mkdir -p test_results
		for _n in ${SOURCE_PKGS}; do
			go test -race -cover -covermode=atomic -coverprofile=test_results/$(echo $_n | sed 's/\//_/g').out ${_n}
		done
		# several tests set the umask to 000, which gets applied to the results files
		chmod u+r test_results/*
		gocoverutil -coverprofile=test_results/cover.report merge test_results/*.out
		goveralls -coverprofile=test_results/cover.report -service=ci
	else
		make test
	fi
}

build_integration() {
	make integration
}

build_release() {
	local _tag _always
	_tag="$(git describe --abbrev=0 2>/dev/null || true)"
	_always="$(git describe --always || true)"
	if [[ $_tag == $_always ]]; then
		build_artifact $_tag "$RELEASE_DIRS"
	fi
}

## Create a distributable tar.gz of all the binaries
build_artifact() {
	local _version="$1" _dirs="$2"
	local _libc _tgz _sum _binaries _n _tmp _tar_opts

	[[ -z "$_dirs" ]] && _dirs="$ARTIFACT_DIRS"
	_binaries="$(find $_dirs -perm -u=x -a -type f)"


	# handle the case that we're building for alpine
	if [[ $OS1 == linux ]]; then
		case $(ldd --version 2>&1) in
			*GLIB*) _libc="-glibc" ;;
			*muslr*) _libc="-musl" ;;
			*) _libc="-unknown" ;;
		esac
		_tar_opts="--owner=root --group=root"
	fi

	if [[ $_version ]]; then
		_tgz="releases/spire-${_version}-${OS1}-${ARCH1}${_libc}.tar.gz"
		_sum="releases/spire-${_version}-${OS1}-${ARCH1}${_libc}_checksums.txt"
		_tmp=".tmp/spire-${_version}"
	else
		_version="$(git log -n1 --pretty=format:%h)"
		_tgz="artifacts/spire-${_version}-${OS1}-${ARCH1}${_libc}.tar.gz"
		_sum="artifacts/spire-${_version}-${OS1}-${ARCH1}${_libc}_checksums.txt"
		_tmp=".tmp/spire"
	fi

	_log_info "creating artifact \"${_tgz}\""

	mkdir -p $(dirname $_tgz)
	rm -rf $(dirname $_tmp)
	mkdir -p $_tmp

	# we munge the file structure a bit here
	for _n in $_binaries; do
		if [[ $_n == *cmd/* ]]; then
			cp $_n $_tmp
		else
			mkdir -p ${_tmp}/$(dirname $(dirname $_n))
			cp -r $_n ${_tmp}/$(dirname $_n)
		fi
	done
	for _n in $RELEASE_FILES; do
		cp -r $_n $_tmp
	done

	tar --directory .tmp $_tar_opts -cvzf $_tgz $(basename $_tmp)
	echo "$(shasum -a 256 $_tgz | cut -d' ' -f1) $(basename $_tgz)" > $_sum
}

build_clean() {
	make clean
}

build_distclean() {
	make distclean
	# remove some additional directories
	rm -rf ${BUILD_DIR}
}

build_all() {
	build_setup
	build_vendor
	build_binaries
	build_test
}


case "$1" in
	env) build_env ;;
	setup) build_setup ;;
	utils) build_utils ;;
	vendor) build_vendor ;;
	protobuf) build_protobuf ;;
	protobuf_verify) build_protobuf_verify ;;
	binaries|bin) build_binaries $2 ;;
	test) build_test ;;
	integration) build_integration ;;
	artifact) build_artifact ;;
	release) build_release ;;
	clean) build_clean ;;
	distclean) build_distclean ;;
	all) build_all ;;
	*) compgen -A function build_ | sed 's/build_/build.sh /' ;;
esac

