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

# For users that wish to run SPIRE containers as a non-root user,
# provide a default unprivileged user such that the default paths
# that SPIRE will try to read from, write to, and create at runtime
# can be given the correct file ownership/permissions at build time.
ARG spireuid=1000
ARG spiregid=1000

# Set up directories that SPIRE expects by default
# Set up base directories
RUN install -d -o root -g root -m 777 /spireroot
RUN install -d -o root -g root -m 755 /spireroot/etc/ssl/certs
RUN install -d -o root -g root -m 755 /spireroot/run
RUN install -d -o root -g root -m 755 /spireroot/var/lib
RUN install -d -o root -g root -m 1777 /spireroot/tmp

# Set up directories used by SPIRE
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireroot/etc/spire
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireroot/run/spire
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireroot/var/lib/spire

# Set up spire-server directories
RUN cp -r /spireroot /spireserverroot
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireserverroot/etc/spire/server
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireserverroot/run/spire/server/private
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireserverroot/var/lib/spire/server

# Set up spire-agent directories
RUN cp -r /spireroot /spireagentroot
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireagentroot/etc/spire/agent
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireagentroot/run/spire/agent/public
RUN install -d -o ${spireuid} -g ${spiregid} -m 755 /spireagentroot/var/lib/spire/agent

RUN xx-go --wrap
RUN set -e ; xx-apk --no-cache --update add build-base musl-dev libseccomp-dev
ENV CGO_ENABLED=1
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    if [ "$TARGETARCH" = "arm64" ]; then CC=aarch64-alpine-linux-musl; elif [ "$TARGETARCH" = "s390x" ]; then CC=s390x-alpine-linux-musl; fi && \
    make build-static git_tag=$TAG git_dirty="" && \
    for f in $(find bin -executable -type f); do xx-verify --static $f; done

FROM --platform=${BUILDPLATFORM} scratch AS spire-base
WORKDIR /opt/spire
CMD []
COPY --link --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# SPIRE Server
FROM spire-base AS spire-server
USER ${spireuid}:${spiregid}
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]
COPY --link --from=builder /spireserverroot /
COPY --link --from=builder /spire/bin/static/spire-server bin/

# SPIRE Agent
FROM spire-base AS spire-agent
USER ${spireuid}:${spiregid}
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]
COPY --link --from=builder /spireagentroot /
COPY --link --from=builder /spire/bin/static/spire-agent bin/

# OIDC Discovery Provider
FROM spire-base AS oidc-discovery-provider
USER ${spireuid}:${spiregid}
ENTRYPOINT ["/opt/spire/bin/oidc-discovery-provider"]
COPY --link --from=builder /spire/bin/static/oidc-discovery-provider bin/
