FROM spire-agent:latest-local AS spire-agent

FROM ghostunnel/ghostunnel:latest AS ghostunnel-latest

FROM alpine/socat:latest AS socat-ghostunnel-agent-mashup
ENTRYPOINT ["/usr/bin/dumb-init", "supervisord", "--nodaemon", "--configuration", "/opt/supervisord/supervisord.conf"]
CMD []
COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
COPY --from=ghostunnel-latest /usr/bin/ghostunnel /usr/bin/ghostunnel
RUN apk --no-cache --update add dumb-init
RUN apk --no-cache --update add supervisor
