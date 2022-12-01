# Build stage
ARG goversion
FROM golang:${goversion}-alpine as builder
WORKDIR /spire
RUN apk --no-cache --update add build-base git mercurial
ADD go.* ./
RUN go mod download
ADD . .
RUN make build

# Common base
FROM alpine AS spire-base
WORKDIR /opt/spire
RUN mkdir -p /opt/spire/bin
CMD []
RUN apk --no-cache --update add dumb-init
RUN apk --no-cache --update add ca-certificates

# SPIRE Server
FROM spire-base AS spire-server
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/spire-server", "run"]
COPY --from=builder /spire/bin/spire-server bin/spire-server

# SPIRE Agent
FROM spire-base AS spire-agent
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/spire-agent", "run"]
COPY --from=builder /spire/bin/spire-agent bin/spire-agent

# K8S Workload Registrar
FROM spire-base AS k8s-workload-registrar
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/k8s-workload-registrar"]
COPY --from=builder /spire/bin/k8s-workload-registrar bin/k8s-workload-registrar

# OIDC Discovery Provider
FROM spire-base AS oidc-discovery-provider
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/oidc-discovery-provider"]
COPY --from=builder /spire/bin/oidc-discovery-provider bin/oidc-discovery-provider
