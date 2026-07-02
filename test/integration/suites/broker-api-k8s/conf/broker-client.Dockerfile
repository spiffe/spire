# Tiny image that just carries the brokerclient binary built on the host.
# We base on busybox so `sleep infinity` is available; the suite scripts
# `kubectl exec` into the pod and invoke /brokerclient with per-test flags.
FROM busybox:1.37
COPY brokerclient /brokerclient
