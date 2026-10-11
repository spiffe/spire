# The xds-control-plane binary is cross-compiled for linux on the host in the
# 00-setup step, so this image only packages the static binary.
FROM scratch
COPY xds-control-plane /xds-control-plane
ENTRYPOINT ["/xds-control-plane"]
