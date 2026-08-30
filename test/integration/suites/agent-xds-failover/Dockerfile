# The xds-control-plane binary is cross-compiled for linux on the host in the
# 00-setup step (mirroring the debugserver/debugagent helpers), so this image
# only needs to package and run the resulting static binary.
FROM alpine:3.18
COPY xds/xds-control-plane /usr/local/bin/xds-control-plane
ENTRYPOINT ["/usr/local/bin/xds-control-plane"]
