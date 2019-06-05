# Build stage
ARG goversion
FROM golang:${goversion}-alpine as builder
RUN apk add build-base git mercurial
# Download modules in a separate step for quicker builds when deps haven't changed
ADD go.mod /spire/go.mod
ADD go.sum /spire/go.sum
RUN cd /spire && go mod download
# Build K8s Workload Registrar
ADD . /spire
RUN cd /spire/support/k8s/k8s-workload-registrar && go test && go build

# Image stage
FROM alpine
RUN apk add dumb-init
RUN mkdir -p /opt/spire/bin
COPY --from=builder /spire/support/k8s/k8s-workload-registrar/k8s-workload-registrar /opt/spire/bin/k8s-workload-registrar
WORKDIR /opt/spire
ENTRYPOINT ["/usr/bin/dumb-init", "/opt/spire/bin/k8s-workload-registrar"]
CMD []
