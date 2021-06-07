# Build stage
ARG goversion
FROM golang:${goversion}-alpine as builder
RUN apk add build-base git mercurial
ADD go.mod /spire/go.mod
RUN cd /spire && go mod download
ADD . /spire
WORKDIR /spire
# RUN make build
# build: tidy bin/spire-server bin/spire-agent bin/k8s-workload-registrar bin/oidc-discovery-provider
RUN make tidy
RUN make bin/k8s-workload-registrar

# Common base
FROM alpine AS spire-base
RUN apk --no-cache add dumb-init
RUN apk --no-cache add ca-certificates
RUN mkdir -p /opt/spire/bin

# K8S Workload Registrar
FROM spire-base AS k8s-workload-registrar
COPY --from=builder /spire/bin/k8s-workload-registrar /opt/spire/bin/k8s-workload-registrar
WORKDIR /opt/spire
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/k8s-workload-registrar"]
CMD []
