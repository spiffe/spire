FROM spire-agent-windows:latest-local as spire-agent-windows

FROM spire-server-windows:latest-local as spire-base

COPY --from=spire-agent-windows C:/spire/bin/spire-agent.exe C:/spire/bin/spire-agent.exe

ENTRYPOINT [ "cmd" ]






