# The canonical spire-server:latest-local image ships a FULLY STATIC musl
# binary, which cannot dlopen() shared objects. The PKCS#11 KeyManager loads
# the SoftHSM module via dlopen at runtime, so the static binary fails with
# "could not open PKCS#11". This image instead compiles a DYNAMICALLY-linked
# spire-server so dlopen works. Build context must be the repo root.
ARG goversion=1.25.6
FROM golang:${goversion}-alpine3.22 AS builder

# build-base provides gcc/musl-dev for cgo (go-sqlite3 etc.).
RUN apk add --no-cache build-base git

WORKDIR /spire
COPY go.* ./
RUN go mod download
COPY . .
# Dynamic link (no -extldflags "-static"); CGO on so the binary can dlopen.
RUN CGO_ENABLED=1 go build -o /spire-server ./cmd/spire-server

FROM alpine:3.18 AS spire-server-hsm
RUN apk add --no-cache softhsm bash
RUN mkdir -p /var/lib/softhsm/tokens

COPY --from=builder /spire-server /opt/spire/bin/spire-server

ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]
