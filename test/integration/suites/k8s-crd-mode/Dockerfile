FROM alpine:3.17 AS example-crd-agent
CMD []
RUN apk add --no-cache --update dumb-init
RUN apk add --no-cache --update openssl

COPY --from=spire-agent-scratch:latest-local /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
