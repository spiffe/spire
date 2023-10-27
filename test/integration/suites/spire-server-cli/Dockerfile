FROM alpine:3.18 AS spire-server-alpine
RUN apk add --no-cache --update openssl
COPY --from=spire-server:latest-local /opt/spire/bin/spire-server /opt/spire/bin/spire-server
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]
