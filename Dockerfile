# Build stage
# syntax = docker/dockerfile:1.4.2@sha256:443aab4ca21183e069e7d8b2dc68006594f40bddf1b15bbd83f5137bd93e80e2
ARG goversion
FROM --platform=${BUILDPLATFORM} golang:${goversion}-alpine as base
WORKDIR /spire
RUN apk --no-cache --update add file bash clang lld pkgconfig git make
COPY go.* ./
# https://go.dev/ref/mod#module-cache
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

# xx is a helper for cross-compilation
# when bumping to a new version analyze the new version for security issues
# then use crane to lookup the digest of that version so we are immutable
# crane digest tonistiigi/xx:1.1.2
FROM --platform=$BUILDPLATFORM tonistiigi/xx@sha256:9dde7edeb9e4a957ce78be9f8c0fbabe0129bf5126933cd3574888f443731cda AS xx

FROM --platform=${BUILDPLATFORM} base as builder
ARG TARGETPLATFORM
ARG TARGETARCH
COPY --link --from=xx / /
RUN install -d -o root -g root -m 1777 /newtmp
RUN xx-go --wrap
RUN set -e ; xx-apk --no-cache --update add build-base musl-dev libseccomp-dev
ENV CGO_ENABLED=1
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    if [ "$TARGETARCH" = "arm64" ]; then CC=aarch64-alpine-linux-musl; fi && \
    make build-static && \
    for f in $(find bin -executable -type f); do xx-verify $f; done

FROM --platform=${BUILDPLATFORM} scratch AS spire-base
WORKDIR /opt/spire
CMD []
COPY --link --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --link --from=builder /newtmp /tmp

# SPIRE Server
FROM spire-base AS spire-server
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]
COPY --link --from=builder /spire/bin/static/spire-server bin/

FROM spire-base AS spire-agent
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]
COPY --link --from=builder /spire/bin/static/spire-agent bin/

# K8S Workload Registrar
FROM spire-base AS k8s-workload-registrar
ENTRYPOINT ["/opt/spire/bin/k8s-workload-registrar"]
COPY --link --from=builder /spire/bin/static/k8s-workload-registrar bin/

# OIDC Discovery Provider
FROM spire-base AS oidc-discovery-provider
ENTRYPOINT ["/opt/spire/bin/oidc-discovery-provider"]
COPY --link --from=builder /spire/bin/static/oidc-discovery-provider bin/
