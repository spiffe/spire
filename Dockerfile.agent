# Build stage
ARG goversion
FROM golang:${goversion}-alpine as builder
RUN apk add build-base git mercurial
# Download modules in a separate step for quicker builds when deps haven't changed
ADD go.mod /spire/go.mod
ADD go.sum /spire/go.sum
RUN cd /spire && go mod download
# Build spire-agent
ADD . /spire
RUN cd /spire && make test && make cmd/spire-agent

# Image stage
FROM alpine
RUN apk add dumb-init 
RUN apk add ca-certificates
RUN mkdir -p /opt/spire/bin
COPY --from=builder /spire/cmd/spire-agent/spire-agent /opt/spire/bin/spire-agent
WORKDIR /opt/spire
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/spire-agent", "run"]
CMD []
