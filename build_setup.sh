#!/bin/bash

set -ex

PROTOBUF_VERSION=${PROTOBUF_VERSION:-3.3.0}
GO_VERSION=${GO_VERSION:-1.8.3}
GLIDE_VERSION=${GLIDE_VERSION:-0.12.3}

go_url="https://storage.googleapis.com/golang"
go_tgz="go${GO_VERSION}.linux-amd64.tar.gz"
pb_url="https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}"
pb_tgz="protoc-${PROTOBUF_VERSION}-linux-x86_64.zip"
glide_url="https://github.com/Masterminds/glide/releases/download/v${GLIDE_VERSION}"
glide_tgz="glide-v${GLIDE_VERSION}-linux-amd64.tar.gz"

fetch_url() {
    if [[ ! -r .cache/${2} ]]; then
        curl --output .cache/${2} --location --silent ${1}/${2}
    fi
}

mkdir -p .cache
fetch_url ${pb_url} ${pb_tgz}
fetch_url ${go_url} ${go_tgz} 
fetch_url ${glide_url} ${glide_tgz} 
  
rm -rf $HOME/golang
tar --directory $HOME --transform 's|^go|golang|' -xf .cache/${go_tgz}

rm -rf $HOME/protobuf
mkdir -p $HOME/protobuf
unzip -qod $HOME/protobuf .cache/${pb_tgz}

rm -rf $HOME/glide
tar --directory $HOME --transform 's|^linux-amd64|glide/bin|' -xf .cache/${glide_tgz}

mkdir -p $HOME/go/src

export GOPATH=$HOME/go
export GOROOT=$HOME/golang
export PATH=$GOROOT/bin:$HOME/glide/bin:$HOME/protobuf/bin:$PATH

go get github.com/golang/protobuf/protoc-gen-go
go get github.com/jstemmer/go-junit-report
go get github.com/AlekSi/gocovermerge
go get github.com/mattn/goveralls

