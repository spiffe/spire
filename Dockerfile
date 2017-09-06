FROM ubuntu:xenial

RUN apt-get update

RUN apt-get -y install \
    software-properties-common python-software-properties

RUN apt-get -y install \
    curl unzip git build-essential

RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update
RUN apt-get -y install golang-go

RUN add-apt-repository ppa:masterminds/glide && apt-get update

RUN apt-get -y install glide

RUN mkdir -p /root/go/src/github.com/spiffe && \
    ln -s /code /root/go/src/github.com/spiffe/sri

ENV GOPATH /root/go
ENV GOROOT /usr/lib/go/
ENV PWD /root/go/src/github.com/spiffe/sri
WORKDIR ${PWD}

# Hack: preserve breadcrumb when WORKDIR is a symlink
CMD ["/bin/bash", \
     "-c", \
     "cd /root/go/src/github.com/spiffe/sri && \
      eval $(./build.sh env) && /bin/bash \
     "]
