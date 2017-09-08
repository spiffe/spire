FROM ubuntu:xenial

RUN apt-get update

RUN apt-get -y install \
    software-properties-common python-software-properties

RUN add-apt-repository ppa:longsleep/golang-backports
RUN add-apt-repository ppa:masterminds/glide

RUN apt-get update

RUN apt-get -y install \
    curl unzip git build-essential

RUN apt-get -y install golang-go glide

RUN mkdir -p /root/go/src/github.com/spiffe/spire

RUN ln -s ~/go/src/github.com/spiffe/spire/.build_cache ~/go/pkg

ENV GOPATH /root/go
ENV GOROOT /usr/lib/go/
ENV PWD /root/go/src/github.com/spiffe/spire
WORKDIR ${PWD}