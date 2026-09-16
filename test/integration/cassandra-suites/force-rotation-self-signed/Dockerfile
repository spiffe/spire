FROM alpine:3.18 AS nested-agent-alpine
RUN apk add --no-cache --update openssl
COPY --from=spire-agent:latest-local /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]
