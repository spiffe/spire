FROM spire-agent:latest-local as spire-agent

FROM oidc-discovery-provider:latest-local as oidc-discovery-provider

FROM alpine:3.18.0 AS oidc-discovery-provider-mashup
COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
COPY --from=oidc-discovery-provider /opt/spire/bin/oidc-discovery-provider /opt/spire/bin/oidc-discovery-provider
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]
CMD []
