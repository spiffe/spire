FROM spire-server-scratch:latest-local AS test-spire-server
FROM alpine:3.17 AS spire-server-alpine
RUN apk add --no-cache --update openssl
COPY --from=test-spire-server /opt/spire/bin/spire-server /opt/spire/bin/spire-server
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]
