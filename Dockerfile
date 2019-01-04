FROM ubuntu:xenial

RUN apt-get update && apt-get -y install \
    curl unzip git build-essential

COPY build.sh /root/
ENV BUILD_DIR=/root/build
RUN /root/build.sh setup

ENV GOPATH=/root/go
ENV GOROOT=/root/build
ENV GOBIN=$GOPATH/bin/linux_amd64
ENV PATH=$GOROOT/bin:$GOBIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN mkdir /root/go
WORKDIR /root/spire
