#!/bin/bash

set -ex

PROTOBUF_VERSION=${PROTOBUF_VERSION:-3.3.0}
GO_VERSION=${GO_VERSION:-1.8.3}

case $(uname) in
    Darwin) os1=darwin; os2=osx ;;
    Linux) os1=linux; os2=linux ;;
esac

case $(uname -m) in
    x86_64) arch1=x86_64; arch2=amd64 ;;
esac

go_url="https://storage.googleapis.com/golang"
go_tgz="go${GO_VERSION}.${os1}-${arch2}.tar.gz"
pb_url="https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}"
pb_tgz="protoc-${PROTOBUF_VERSION}-${os2}-${arch1}.zip"

fetch_url() {
    if [[ ! -r .cache/${2} ]]; then
        curl --output .cache/${2} --location --silent ${1}/${2}
    fi
}

mkdir -p .cache
fetch_url ${pb_url} ${pb_tgz}
fetch_url ${go_url} ${go_tgz} 
  
mkdir -p .build/protobuf
unzip -qod .build/protobuf .cache/${pb_tgz}

tar --directory .build -xf .cache/${go_tgz}

export GOROOT=$PWD/.build/go
export GOPATH=$PWD/.build
export PATH=$GOROOT/bin:$PATH

go get -u github.com/golang/protobuf/protoc-gen-go

