FROM ubuntu:xenial

RUN apt-get update && apt-get -y install \
    curl unzip git build-essential

RUN mkdir -p /root/go/src/github.com/spiffe && \
    ln -s /code /root/go/src/github.com/spiffe/sri

WORKDIR /root/go/src/github.com/spiffe/sri

# Hack: preserve breadcrumb when WORKDIR is a symlink
CMD ["/bin/bash", \
     "-c", \
     "cd /root/go/src/github.com/spiffe/sri && \
      eval $(./build.sh env) && /bin/bash \
     "]
