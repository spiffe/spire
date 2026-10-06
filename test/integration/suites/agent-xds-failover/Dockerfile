# The xds-control-plane binary is cross-compiled for linux on the host in the
# 00-setup step, so this image only packages the static binary.
FROM alpine:3.18
COPY xds-control-plane /usr/local/bin/xds-control-plane
ENTRYPOINT ["/usr/local/bin/xds-control-plane"]
