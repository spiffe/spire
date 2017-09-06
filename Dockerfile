FROM ubuntu:xenial

RUN apt-get update && apt-get -y install \
    curl unzip git build-essential

RUN mkdir -p /root/go/src/github.com/spiffe && \
    ln -s /code /root/go/src/github.com/spiffe/spire

WORKDIR /root/go/src/github.com/spiffe/spire

# Hack: preserve breadcrumb when WORKDIR is a symlink
CMD ["/bin/bash", \
     "-c", \
     "cd /root/go/src/github.com/spiffe/spire && \
      eval $(./build.sh env) && /bin/bash \
     "]
