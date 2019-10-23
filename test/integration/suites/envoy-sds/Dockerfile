FROM spire-agent:latest-local as spire-agent

FROM envoyproxy/envoy-alpine:latest AS envoy-agent-mashup
COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
RUN apk --no-cache add dumb-init
RUN apk --no-cache add supervisor
COPY conf/supervisord.conf /etc/
ENTRYPOINT ["/usr/bin/dumb-init", "supervisord", "--nodaemon", "--configuration", "/etc/supervisord.conf"]
CMD []
