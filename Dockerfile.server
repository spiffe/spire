# Build stage
ARG goversion
FROM golang:${goversion}-alpine as builder
RUN apk add build-base git mercurial
# Download modules in a separate step for quicker builds when deps haven't changed
ADD go.mod /spire/go.mod
ADD go.sum /spire/go.sum
RUN cd /spire && go mod download
# Build spire-server
ADD . /spire
RUN cd /spire && make test && make cmd/spire-server

# Image stage
FROM alpine
RUN apk add dumb-init 
RUN apk add ca-certificates
RUN mkdir -p /opt/spire/bin
COPY --from=builder /spire/cmd/spire-server/spire-server /opt/spire/bin/spire-server
WORKDIR /opt/spire
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/spire-server", "run"]
CMD []
