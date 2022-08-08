DIR := ${CURDIR}

# There is no reason GOROOT should be set anymore. Unset it so it doesn't mess
# with our go toolchain detection/usage.
ifneq ($(GOROOT),)
	export GOROOT=
endif

E:=@
ifeq ($(V),1)
	E=
endif

cyan := $(shell which tput > /dev/null && tput setaf 6 2>/dev/null || echo "")
reset := $(shell which tput > /dev/null && tput sgr0 2>/dev/null || echo "")
bold  := $(shell which tput > /dev/null && tput bold 2>/dev/null || echo "")

.PHONY: default all help

default: build

all: build lint test

help:
	@echo "$(bold)Usage:$(reset) make $(cyan)<target>$(reset)"
	@echo
	@echo "$(bold)Build:$(reset)"
	@echo "  $(cyan)build$(reset)                                 - build all SPIRE binaries (default)"
	@echo "  $(cyan)artifact$(reset)                              - build SPIRE tarball artifact"
	@echo
	@echo "$(bold)Test:$(reset)"
	@echo "  $(cyan)test$(reset)                                  - run unit tests"
	@echo "  $(cyan)race-test$(reset)                             - run unit tests with race detection"
	@echo "  $(cyan)integration$(reset)                           - run integration tests (requires Docker images)"
	@echo "                                          support 'SUITES' variable for executing specific tests"
	@echo "                                          e.g. SUITES='suites/join-token suites/k8s' make integration"
	@echo "  $(cyan)integration-windows$(reset)                   - run integration tests for windows (requires Docker images)"
	@echo "                                          support 'SUITES' variable for executing specific tests"
	@echo "                                          e.g. SUITES='windows-suites/windows-workload-attestor' make integration-windows"
	@echo
	@echo "$(bold)Build and test:$(reset)"
	@echo "  $(cyan)all$(reset)                                   - build all SPIRE binaries, lint the code, and run unit tests"
	@echo
	@echo "$(bold)Docker image:$(reset)"
	@echo "  $(cyan)images$(reset)                                - build all SPIRE Docker images"
	@echo "  $(cyan)spire-server-image$(reset)                    - build SPIRE server Docker image"
	@echo "  $(cyan)spire-agent-image$(reset)                     - build SPIRE agent Docker image"
	@echo "  $(cyan)k8s-workload-registrar-image$(reset)          - build Kubernetes Workload Registrar Docker image"
	@echo "  $(cyan)oidc-discovery-provider-image$(reset)         - build OIDC Discovery Provider Docker image"
	@echo "$(bold)Docker from scratch image:$(reset)"
	@echo "  $(cyan)scratch-images$(reset)                        - build all SPIRE Docker from scratch images"
	@echo "  $(cyan)spire-server-scratch-image$(reset)            - build SPIRE server Docker scratch image"
	@echo "  $(cyan)spire-agent-scratch-image$(reset)             - build SPIRE agent Docker scratch image"
	@echo "  $(cyan)k8s-workload-registrar-scratch-image$(reset)  - build Kubernetes Workload Registrar Docker scratch image"
	@echo "  $(cyan)oidc-discovery-provider-scratch-image$(reset) - build OIDC Discovery Provider Docker image"
	@echo "$(bold)Windows docker image:$(reset)"
	@echo "  $(cyan)images-windows$(reset)                        - build all SPIRE Docker images for windows"
	@echo "  $(cyan)spire-server-image-windows$(reset)            - build SPIRE server Docker image for windows"
	@echo "  $(cyan)spire-agent-image-windows$(reset)             - build SPIRE agent Docker image for windows"
	@echo "  $(cyan)k8s-workload-registrar-image-windows$(reset)  - build Kubernetes Workload Registrar Docker image for windows"
	@echo "  $(cyan)oidc-discovery-provider-image-windows$(reset) - build OIDC Discovery Provider Docker image for windows"
	@echo "$(bold)Developer support:$(reset)"
	@echo "  $(cyan)dev-image$(reset)                             - build the development Docker image"
	@echo "  $(cyan)dev-shell$(reset)                             - run a shell in a development Docker container"
	@echo
	@echo "$(bold)Code generation:$(reset)"
	@echo "  $(cyan)generate$(reset)                              - generate protocol buffers and plugin interface code"
	@echo "  $(cyan)generate-check$(reset)                        - ensure generated code is up to date"
	@echo
	@echo "For verbose output set V=1"
	@echo "  for example: $(cyan)make V=1 build$(reset)"

# Used to force some rules to run every time
FORCE: ;

############################################################################
# OS/ARCH detection
############################################################################
os1=$(shell uname -s)
os2=
ifeq ($(os1),Darwin)
os1=darwin
os2=osx
else ifeq ($(os1),Linux)
os1=linux
os2=linux
else ifeq (,$(findstring MYSYS_NT-10-0-, $(os1)))
os1=windows
os2=windows
else
$(error unsupported OS: $(os1))
endif

arch1=$(shell uname -m)
ifeq ($(arch1),x86_64)
arch2=amd64
else ifeq ($(arch1),aarch64)
arch2=arm64
else ifeq ($(arch1),arm64)
arch2=arm64
else
$(error unsupported ARCH: $(arch1))
endif

############################################################################
# Vars
############################################################################

build_dir := $(DIR)/.build/$(os1)-$(arch1)

go_version_full := $(shell cat .go-version)
go_version := $(go_version_full:.0=)
go_dir := $(build_dir)/go/$(go_version)

ifeq ($(os1),windows)
	go_bin_dir = $(go_dir)/go/bin
	go_url = https://storage.googleapis.com/golang/go$(go_version).$(os1)-$(arch2).zip
	exe=".exe"
else
	go_bin_dir = $(go_dir)/bin
	go_url = https://storage.googleapis.com/golang/go$(go_version).$(os1)-$(arch2).tar.gz
	exe=
endif

go_path := PATH="$(go_bin_dir):$(PATH)"

golangci_lint_version = v1.48.0
golangci_lint_dir = $(build_dir)/golangci_lint/$(golangci_lint_version)
golangci_lint_bin = $(golangci_lint_dir)/golangci-lint
golangci_lint_cache = $(golangci_lint_dir)/cache

protoc_version = 3.20.1
ifeq ($(os1),windows)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-win64.zip
else ifeq ($(arch2),arm64)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-aarch_64.zip
else
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-$(arch1).zip
endif
protoc_dir = $(build_dir)/protoc/$(protoc_version)
protoc_bin = $(protoc_dir)/bin/protoc

protoc_gen_go_version := $(shell grep google.golang.org/protobuf go.mod | awk '{print $$2}')
protoc_gen_go_base_dir := $(build_dir)/protoc-gen-go
protoc_gen_go_dir := $(protoc_gen_go_base_dir)/$(protoc_gen_go_version)-go$(go_version)
protoc_gen_go_bin := $(protoc_gen_go_dir)/protoc-gen-go

protoc_gen_go_grpc_version := v1.1.0
protoc_gen_go_grpc_base_dir := $(build_dir)/protoc-gen-go-grpc
protoc_gen_go_grpc_dir := $(protoc_gen_go_grpc_base_dir)/$(protoc_gen_go_grpc_version)-go$(go_version)
protoc_gen_go_grpc_bin := $(protoc_gen_go_grpc_dir)/protoc-gen-go-grpc

protoc_gen_go_spire_version := $(shell grep github.com/spiffe/spire-plugin-sdk go.mod | awk '{print $$2}')
protoc_gen_go_spire_base_dir := $(build_dir)/protoc-gen-go-spire
protoc_gen_go_spire_dir := $(protoc_gen_go_spire_base_dir)/$(protoc_gen_go_spire_version)-go$(go_version)
protoc_gen_go_spire_bin := $(protoc_gen_go_spire_dir)/protoc-gen-go-spire

# There may be more than one tag. Only use one that starts with 'v' followed by
# a number, e.g., v0.9.3.
git_tag := $(shell git tag --points-at HEAD | grep '^v[0-9]*')
git_hash := $(shell git rev-parse --short=7 HEAD)
git_dirty := $(shell git status -s)

protos := \
	proto/private/server/journal/journal.proto \
	proto/spire/common/common.proto \

api-protos := \

plugin-protos := \
	proto/spire/common/plugin/plugin.proto 

service-protos := \

# The following vars are used in rule construction
comma := ,
null  :=
space := $(null) #

#############################################################################
# Utility functions and targets
#############################################################################

.PHONY: git-clean-check

tolower = $(shell echo $1 | tr '[:upper:]' '[:lower:]')

goenv = $(shell PATH="$(go_bin_dir):$(PATH)" go env $1)

git-clean-check:
ifneq ($(git_dirty),)
	git diff
	@echo "Git repository is dirty!"
	@false
else
	@echo "Git repository is clean."
endif

############################################################################
# Determine go flags
############################################################################

# Flags passed to all invocations of go test
go_test_flags := -timeout=60s

go_flags :=
ifneq ($(GOPARALLEL),)
	go_flags += -p=$(GOPARALLEL)
endif

ifneq ($(GOVERBOSE),)
	go_flags += -v
endif

# Determine the ldflags passed to the go linker. The git tag and hash will be
# provided to the linker unless the git status is dirty.
go_ldflags := -s -w
ifeq ($(git_dirty),)
	ifneq ($(git_tag),)
		# Remove the "v" prefix from the git_tag for use as the version number.
		# e.g. 0.9.3 instead of v0.9.3
		git_version_tag := $(git_tag:v%=%)
		go_ldflags += -X github.com/spiffe/spire/pkg/common/version.gittag=$(git_version_tag)
	endif
	ifneq ($(git_hash),)
		go_ldflags += -X github.com/spiffe/spire/pkg/common/version.githash=$(git_hash)
	endif
endif
go_ldflags := '${go_ldflags}'

#############################################################################
# Build Targets
#############################################################################

.PHONY: build

build: tidy bin/spire-server bin/spire-agent bin/k8s-workload-registrar bin/oidc-discovery-provider

define binary_rule
.PHONY: $1
$1: | go-check bin/
	@echo Building $1...
	$(E)$(go_path) go build $$(go_flags) -ldflags $$(go_ldflags) -o $1$(exe) $2
endef

# main SPIRE binaries
$(eval $(call binary_rule,bin/spire-server,./cmd/spire-server))
$(eval $(call binary_rule,bin/spire-agent,./cmd/spire-agent))
$(eval $(call binary_rule,bin/k8s-workload-registrar,./support/k8s/k8s-workload-registrar))
$(eval $(call binary_rule,bin/oidc-discovery-provider,./support/oidc-discovery-provider))

bin/:
	@mkdir -p $@

#############################################################################
# Build Static binaries for scratch docker images
#############################################################################

.PHONY: build-static

build-static: tidy bin/spire-server-static bin/spire-agent-static bin/k8s-workload-registrar-static bin/oidc-discovery-provider-static

# https://7thzero.com/blog/golang-w-sqlite3-docker-scratch-image
define binary_rule_static
.PHONY: $1
$1: | go-check bin/
	@echo Building $1...
	$(E)$(go_path) CGO_ENABLED=1 go build $$(go_flags) -ldflags '-s -w -linkmode external -extldflags "-static"' -o $1$(exe) $2

endef

# static builds
$(eval $(call binary_rule_static,bin/spire-server-static,./cmd/spire-server))
$(eval $(call binary_rule_static,bin/spire-agent-static,./cmd/spire-agent))
$(eval $(call binary_rule_static,bin/k8s-workload-registrar-static,./support/k8s/k8s-workload-registrar))
$(eval $(call binary_rule_static,bin/oidc-discovery-provider-static,./support/oidc-discovery-provider))

#############################################################################
# Test Targets
#############################################################################

.PHONY: test race-test integration integration-windows

test: | go-check
ifneq ($(COVERPROFILE),)
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) -covermode=atomic -coverprofile="$(COVERPROFILE)" ./...
else
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) ./...
endif

race-test: | go-check
ifneq ($(COVERPROFILE),)
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) -race -coverprofile="$(COVERPROFILE)" ./...
else
	$(E)$(go_path) go test $(go_flags) $(go_test_flags) -race ./...
endif

ci-race-test: | go-check
ifneq ($(COVERPROFILE),)
	$(E)SKIP_FLAKY_TESTS_UNDER_RACE_DETECTOR=1 $(go_path) go test $(go_flags) $(go_test_flags) -race -count=1 -coverprofile="$(COVERPROFILE)" ./...
else
	$(E)SKIP_FLAKY_TESTS_UNDER_RACE_DETECTOR=1 $(go_path) go test $(go_flags) $(go_test_flags) -race -count=1 ./...
endif

integration:
ifeq ($(os1), windows)
	$(error Integration tests are not supported on windows)
else
	$(E)./test/integration/test.sh $(SUITES)
endif

integration-windows:
	$(E)./test/integration/test-windows.sh $(SUITES)

#############################################################################
# Build Artifact
#############################################################################

.PHONY: artifact

artifact: build
	$(E)OUTDIR="$(OUTDIR)" TAG="$(TAG)" ./script/build-artifact.sh

#############################################################################
# Docker Images
#############################################################################

.PHONY: images
images: spire-server-image spire-agent-image k8s-workload-registrar-image oidc-discovery-provider-image

.PHONY: spire-server-image
spire-server-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target spire-server -t spire-server .
	docker tag spire-server:latest spire-server:latest-local

.PHONY: spire-agent-image
spire-agent-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target spire-agent -t spire-agent .
	docker tag spire-agent:latest spire-agent:latest-local

.PHONY: k8s-workload-registrar-image
k8s-workload-registrar-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target k8s-workload-registrar -t k8s-workload-registrar .
	docker tag k8s-workload-registrar:latest k8s-workload-registrar:latest-local

.PHONY: oidc-discovery-provider-image
oidc-discovery-provider-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target oidc-discovery-provider -t oidc-discovery-provider .
	docker tag oidc-discovery-provider:latest oidc-discovery-provider:latest-local

#############################################################################
# Docker Images FROM scratch
#############################################################################

.PHONY: scratch-images
scratch-images: spire-server-scratch-image spire-agent-scratch-image k8s-workload-registrar-scratch-image oidc-discovery-provider-scratch-image

.PHONY: spire-server-scratch-image
spire-server-scratch-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target spire-server-scratch -t spire-server-scratch -f Dockerfile.scratch .
	docker tag spire-server-scratch:latest spire-server-scratch:latest-local

.PHONY: spire-agent-scratch-image
spire-agent-scratch-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target spire-agent-scratch -t spire-agent-scratch -f Dockerfile.scratch .
	docker tag spire-agent-scratch:latest spire-agent-scratch:latest-local

.PHONY: k8s-workload-registrar-scratch-image
k8s-workload-registrar-scratch-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target k8s-workload-registrar-scratch -t k8s-workload-registrar-scratch -f Dockerfile.scratch .
	docker tag k8s-workload-registrar-scratch:latest k8s-workload-registrar-scratch:latest-local

.PHONY: oidc-discovery-provider-scratch-image
oidc-discovery-provider-scratch-image: Dockerfile
	docker build --build-arg goversion=$(go_version_full) --target oidc-discovery-provider-scratch -t oidc-discovery-provider-scratch -f Dockerfile.scratch .
	docker tag oidc-discovery-provider-scratch:latest oidc-discovery-provider-scratch:latest-local

#############################################################################
# Docker Images
#############################################################################

.PHONY: images-windows
images-windows: spire-server-image-windows spire-agent-image-windows oidc-discovery-provider-image-windows

.PHONY: spire-server-image-windows
spire-server-image-windows: Dockerfile
	docker build -f Dockerfile.windows --target spire-server-windows -t spire-server-windows .
	docker tag spire-server-windows:latest spire-server-windows:latest-local

.PHONY: spire-agent-image-windows
spire-agent-image-windows: Dockerfile
	docker build -f Dockerfile.windows --target spire-agent-windows -t spire-agent-windows .
	docker tag spire-agent-windows:latest spire-agent-windows:latest-local

.PHONY: k8s-workload-registrar-image-windows
k8s-workload-registrar-image-windows: Dockerfile
	docker build -f Dockerfile.windows --target k8s-workload-registrar-windows -t k8s-workload-registrar-windows .
	docker tag k8s-workload-registrar-windows:latest k8s-workload-registrar-windows:latest-local

.PHONY: oidc-discovery-provider-image-windows
oidc-discovery-provider-image-windows: Dockerfile
	docker build -f Dockerfile.windows --target oidc-discovery-provider-windows -t oidc-discovery-provider-windows .
	docker tag oidc-discovery-provider-windows:latest oidc-discovery-provider-windows:latest-local

#############################################################################
# Code cleanliness
#############################################################################

.PHONY: tidy tidy-check lint lint-code
tidy: | go-check
	$(E)$(go_path) go mod tidy
	$(E)cd proto/spire; $(go_path) go mod tidy

tidy-check:
ifneq ($(git_dirty),)
	$(error tidy-check must be invoked on a clean repository)
endif
	@echo "Running go tidy..."
	$(E)$(MAKE) tidy
	@echo "Ensuring git repository is clean..."
	$(E)$(MAKE) git-clean-check

lint: lint-code

lint-code: $(golangci_lint_bin)
	$(E)PATH="$(go_bin_dir):$(PATH)" GOLANGCI_LINT_CACHE="$(golangci_lint_cache)" $(golangci_lint_bin) run ./...


#############################################################################
# Code Generation
#############################################################################

.PHONY: generate generate-check

generate: $(protos:.proto=.pb.go) \
	$(api-protos:.proto=.pb.go) \
	$(api-protos:.proto=_grpc.pb.go) \
	$(plugin-protos:.proto=.pb.go) \
	$(plugin-protos:.proto=_grpc.pb.go) \
	$(plugin-protos:.proto=_spire_plugin.pb.go) \
	$(service-protos:.proto=.pb.go) \
	$(service-protos:.proto=_grpc.pb.go) \
	$(service-protos:.proto=_spire_service.pb.go)

%_spire_plugin.pb.go: %.proto $(protoc_bin) $(protoc_gen_go_spire_bin) FORCE | bin/protoc-gen-go-spire
	@echo "generating $@..."
	$(E) PATH="$(protoc_gen_go_spire_dir):$(PATH)" $(protoc_bin) \
		-I proto \
		--go-spire_out=. \
		--go-spire_opt=module=github.com/spiffe/spire \
		--go-spire_opt=mode=plugin \
		$<

%_spire_service.pb.go: %.proto $(protoc_bin) $(protoc_gen_go_spire_bin) FORCE | bin/protoc-gen-go-spire
	@echo "generating $@..."
	$(E) PATH="$(protoc_gen_go_spire_dir):$(PATH)" $(protoc_bin) \
		-I proto \
		--go-spire_out=. \
		--go-spire_opt=module=github.com/spiffe/spire \
		--go-spire_opt=mode=service \
		$<

%_grpc.pb.go: %.proto $(protoc_bin) $(protoc_gen_go_grpc_bin) FORCE
	@echo "generating $@..."
	$(E) PATH="$(protoc_gen_go_grpc_dir):$(PATH)" $(protoc_bin) \
		-I proto \
		--go-grpc_out=. --go-grpc_opt=module=github.com/spiffe/spire \
		$<

%.pb.go: %.proto $(protoc_bin) $(protoc_gen_go_bin) FORCE
	@echo "generating $@..."
	$(E) PATH="$(protoc_gen_go_dir):$(PATH)" $(protoc_bin) \
		-I proto \
		--go_out=. --go_opt=module=github.com/spiffe/spire \
		$<

generate-check:
ifneq ($(git_dirty),)
	$(error protogen-check must be invoked on a clean repository)
endif
	@echo "Compiling protocol buffers..."
	$(E)$(MAKE) generate
	@echo "Ensuring git repository is clean..."
	$(E)$(MAKE) git-clean-check

#############################################################################
# Developer support
#############################################################################

.PHONY: dev-shell dev-image

dev-image:
	$(E)docker build -t spire-dev -f Dockerfile.dev .

dev-shell: | go-check
	$(E)docker run --rm -v "$(call goenv,GOCACHE)":/root/.cache/go-build -v "$(DIR):/spire" -v "$(call goenv,GOPATH)/pkg/mod":/root/go/pkg/mod -it -h spire-dev spire-dev

#############################################################################
# Toolchain
#############################################################################

# go-check checks to see if there is a version of Go available matching the
# required version. The build cache is preferred. If not available, it is
# downloaded into the build cache. Any rule needing to invoke tools in the go
# toolchain should depend on this rule and then prepend $(go_bin_dir) to their
# path before invoking go or use $(go_path) go which already has the path prepended.
# Note that some tools (e.g. anything that uses golang.org/x/tools/go/packages)
# execute on the go binary and also need the right path in order to locate the
# correct go binary.
go-check:
ifeq (go$(go_version), $(shell $(go_path) go version 2>/dev/null | cut -f3 -d' '))
else ifeq ($(os1),windows)
	@echo "Installing go$(go_version)..."
	$(E)rm -rf $(dir $(go_dir))
	$(E)mkdir -p $(go_dir)
	$(E)curl -o $(go_dir)\go.zip -sSfL $(go_url)
	$(E)unzip -qq $(go_dir)\go.zip -d $(go_dir)
else
	@echo "Installing go$(go_version)..."
	$(E)rm -rf $(dir $(go_dir))
	$(E)mkdir -p $(go_dir)
	$(E)curl -sSfL $(go_url) | tar xz -C $(go_dir) --strip-components=1
endif

go-bin-path: go-check
	@echo "$(go_bin_dir):${PATH}"

install-toolchain: install-protoc install-golangci-lint install-protoc-gen-go install-protoc-gen-doc | go-check

install-protoc: $(protoc_bin)

$(protoc_bin):
	@echo "Installing protoc $(protoc_version)..."
	$(E)rm -rf $(dir $(protoc_dir))
	$(E)mkdir -p $(protoc_dir)
	$(E)curl -sSfL $(protoc_url) -o $(build_dir)/tmp.zip; unzip -q -d $(protoc_dir) $(build_dir)/tmp.zip; rm $(build_dir)/tmp.zip

install-golangci-lint: $(golangci_lint_bin)

$(golangci_lint_bin): | go-check
	@echo "Installing golangci-lint $(golangci_lint_version)..."
	$(E)rm -rf $(dir $(golangci_lint_dir))
	$(E)mkdir -p $(golangci_lint_dir)
	$(E)mkdir -p $(golangci_lint_cache)
	$(E)GOBIN=$(golangci_lint_dir) $(go_path) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_lint_version)

install-protoc-gen-go: $(protoc_gen_go_bin)

$(protoc_gen_go_bin): | go-check
	@echo "Installing protoc-gen-go $(protoc_gen_go_version)..."
	$(E)rm -rf $(protoc_gen_go_base_dir)
	$(E)mkdir -p $(protoc_gen_go_dir)
	$(E)GOBIN=$(protoc_gen_go_dir) $(go_path) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(protoc_gen_go_version)

install-protoc-gen-go-grpc: $(protoc_gen_go_grpc_bin)

$(protoc_gen_go_grpc_bin): | go-check
	@echo "Installing protoc-gen-go-grpc $(protoc_gen_go_grpc_version)..."
	$(E)rm -rf $(protoc_gen_go_grpc_base_dir)
	$(E)mkdir -p $(protoc_gen_go_grpc_dir)
	$(E)GOBIN=$(protoc_gen_go_grpc_dir) $(go_path) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(protoc_gen_go_grpc_version)

install-protoc-gen-go-spire: $(protoc_gen_go_spire_bin)

$(protoc_gen_go_spire_bin): | go-check
	@echo "Installing protoc-gen-go-spire $(protoc_gen_go_spire_version)..."
	$(E)rm -rf $(protoc_gen_go_spire_base_dir)
	$(E)mkdir -p $(protoc_gen_go_spire_dir)
	$(E)GOBIN=$(protoc_gen_go_spire_dir) $(go_path) go install github.com/spiffe/spire-plugin-sdk/cmd/protoc-gen-go-spire@$(protoc_gen_go_spire_version)
