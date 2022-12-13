FROM spire-agent-scratch:latest-local AS spire-agent

FROM alpine:3.17 AS example-crd-agent
RUN apk add --no-cache --update dumb-init
RUN apk add --no-cache --update openssl

COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
CMD []
