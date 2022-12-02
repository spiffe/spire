# Build stage
# syntax = docker/dockerfile:1.4.2@sha256:443aab4ca21183e069e7d8b2dc68006594f40bddf1b15bbd83f5137bd93e80e2
ARG goversion
FROM --platform=${BUILDPLATFORM} golang:${goversion}-alpine as base
WORKDIR /spire
COPY go.* ./
# https://go.dev/ref/mod#module-cache
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

FROM base as builder
ARG TARGETOS TARGETARCH
RUN apk --no-cache --update add build-base git mercurial
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    make build

# Common base
FROM --platform=${BUILDPLATFORM} alpine AS spire-base
WORKDIR /opt/spire
CMD []
RUN apk --no-cache --update add dumb-init
RUN apk --no-cache --update add ca-certificates

# SPIRE Server
FROM spire-base AS spire-server
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/spire-server", "run"]
COPY --link --from=builder /spire/bin/spire-server bin/spire-server

# SPIRE Agent
FROM spire-base AS spire-agent
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/spire-agent", "run"]
COPY --link --from=builder /spire/bin/spire-agent bin/spire-agent

# K8S Workload Registrar
FROM spire-base AS k8s-workload-registrar
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/k8s-workload-registrar"]
COPY --link --from=builder /spire/bin/k8s-workload-registrar bin/k8s-workload-registrar

# OIDC Discovery Provider
FROM spire-base AS oidc-discovery-provider
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/oidc-discovery-provider"]
COPY --link --from=builder /spire/bin/oidc-discovery-provider bin/oidc-discovery-provider
