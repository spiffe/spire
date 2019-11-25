FROM spire-agent:latest-local as spire-agent

FROM alpine/socat:latest AS socat-latest

FROM squareup/ghostunnel:latest AS socat-ghostunnel-agent-mashup
COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
COPY --from=socat-latest /usr/bin/socat /usr/bin/socat
RUN apk --no-cache add dumb-init
RUN apk --no-cache add supervisor
ENTRYPOINT ["/usr/bin/dumb-init", "supervisord", "--nodaemon", "--configuration", "/opt/supervisord/supervisord.conf"]
CMD []
