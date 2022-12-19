FROM alpine:3.17 as nested-agent-alpine
RUN apk add --no-cache --update openssl
COPY --from=spire-agent-scratch:latest-local /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]
