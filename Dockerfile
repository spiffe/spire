# syntax = docker/dockerfile:1.6.0@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021

# Build stage
ARG goversion
# Use alpine3.18 until go-sqlite works in 3.19
FROM --platform=${BUILDPLATFORM} golang:${goversion}-alpine3.18 as base
WORKDIR /spire
RUN apk --no-cache --update add file bash clang lld pkgconfig git make
COPY go.* ./
# https://go.dev/ref/mod#module-cache
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

# xx is a helper for cross-compilation
# when bumping to a new version analyze the new version for security issues
# then use crane to lookup the digest of that version so we are immutable
# crane digest tonistiigi/xx:1.3.0
FROM --platform=$BUILDPLATFORM tonistiigi/xx@sha256:904fe94f236d36d65aeb5a2462f88f2c537b8360475f6342e7599194f291fb7e AS xx

FROM --platform=${BUILDPLATFORM} base as builder
ARG TAG
ARG TARGETPLATFORM
ARG TARGETARCH
COPY --link --from=xx / /

# Set up directories that SPIRE expects by default
# Set up base directories
RUN install -d /spireroot
RUN install -d /spireroot/etc/ssl/certs
RUN install -d /spireroot/run
RUN install -d /spireroot/var/lib
RUN install -d /spireroot/tmp

# Set up directories used by SPIRE
RUN install -d /spireroot/opt/spire
RUN install -d /spireroot/etc/spire
RUN install -d /spireroot/run/spire
RUN install -d /spireroot/var/lib/spire

# Set up spire-server directories
RUN cp -r /spireroot /spireserverroot
RUN install -d /spireserverroot/etc/spire/server
RUN install -d /spireserverroot/run/spire/server/private
RUN install -d /spireserverroot/var/lib/spire/server

# Set up spire-agent directories
RUN cp -r /spireroot /spireagentroot
RUN install -d /spireagentroot/etc/spire/agent
RUN install -d /spireagentroot/run/spire/agent/public
RUN install -d /spireagentroot/var/lib/spire/agent

RUN xx-go --wrap
RUN set -e ; xx-apk --no-cache --update add build-base musl-dev libseccomp-dev
ENV CGO_ENABLED=1
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    if [ "$TARGETARCH" = "arm64" ]; then CC=aarch64-alpine-linux-musl; elif [ "$TARGETARCH" = "s390x" ]; then CC=s390x-alpine-linux-musl; fi && \
    make build-static git_tag=$TAG git_dirty="" && \
    for f in $(find bin -executable -type f); do xx-verify $f; done

FROM --platform=${BUILDPLATFORM} scratch AS spire-base
CMD []
COPY --link --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# SPIRE Server
FROM spire-base AS spire-server
# For users that wish to run SPIRE containers as a non-root user,
# provide a default unprivileged user such that the default paths
# that SPIRE will try to read from, write to, and create at runtime
# can be given the correct file ownership/permissions at build time.
ARG spireuid=1000
ARG spiregid=1000
USER ${spireuid}:${spiregid}
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]
COPY --link --from=builder --chown=${spireuid}:${spiregid} --chmod=755 /spireserverroot /
COPY --link --from=builder --chown=${spireuid}:${spiregid} --chmod=755 /spire/bin/static/spire-server /opt/spire/bin/
WORKDIR /opt/spire

# SPIRE Agent
FROM spire-base AS spire-agent
ARG spireuid=1000
ARG spiregid=1000
USER ${spireuid}:${spiregid}
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]
COPY --link --from=builder --chown=${spireuid}:${spiregid} --chmod=755 /spireagentroot /
COPY --link --from=builder --chown=${spireuid}:${spiregid} --chmod=755 /spire/bin/static/spire-agent /opt/spire/bin/
WORKDIR /opt/spire

# OIDC Discovery Provider
FROM spire-base AS oidc-discovery-provider
ARG spireuid=1000
ARG spiregid=1000
USER ${spireuid}:${spiregid}
ENTRYPOINT ["/opt/spire/bin/oidc-discovery-provider"]
COPY --link --from=builder --chown=${spireuid}:${spiregid} --chmod=755 /spire/bin/static/oidc-discovery-provider /opt/spire/bin/
WORKDIR /opt/spire
