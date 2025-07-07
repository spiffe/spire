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
	@echo
	@echo "$(bold)Test:$(reset)"
	@echo "  $(cyan)test$(reset)                                  - run unit tests"
	@echo "  $(cyan)race-test$(reset)                             - run unit tests with race detection"
	@echo "  $(cyan)integration$(reset)                           - run integration tests (requires Docker images)"
	@echo "                                          support 'SUITES' variable for executing specific tests"
	@echo "                                          and 'IGNORE_SUITES' variable for ignoring tests"
	@echo "                                          e.g. SUITES='suites/join-token suites/k8s' make integration"
	@echo "  $(cyan)integration-windows$(reset)                   - run integration tests for windows (requires Docker images)"
	@echo "                                          support 'SUITES' variable for executing specific tests"
	@echo "                                          e.g. SUITES='windows-suites/windows-workload-attestor' make integration-windows"
	@echo
	@echo "$(bold)Lint:$(reset)"
	@echo "  $(cyan)lint$(reset)                                  - lint the code and markdown files"
	@echo "  $(cyan)lint-code$(reset)                             - lint the code"
	@echo "  $(cyan)lint-md$(reset)                               - lint markdown files"
	@echo
	@echo "$(bold)Build, lint and test:$(reset)"
	@echo "  $(cyan)all$(reset)                                   - build all SPIRE binaries, run linters and unit tests"
	@echo
	@echo "$(bold)Docker image:$(reset)"
	@echo "  $(cyan)images$(reset)                                - build all SPIRE Docker images"
	@echo "  $(cyan)images-no-load$(reset)                        - build all SPIRE Docker images but don't load them into the local docker registry"
	@echo "  $(cyan)spire-server-image$(reset)                    - build SPIRE server Docker image"
	@echo "  $(cyan)spire-agent-image$(reset)                     - build SPIRE agent Docker image"
	@echo "  $(cyan)oidc-discovery-provider-image$(reset)         - build OIDC Discovery Provider Docker image"
	@echo "$(bold)Windows docker image:$(reset)"
	@echo "  $(cyan)images-windows$(reset)                        - build all SPIRE Docker images for windows"
	@echo "  $(cyan)spire-server-image-windows$(reset)            - build SPIRE server Docker image for windows"
	@echo "  $(cyan)spire-agent-image-windows$(reset)             - build SPIRE agent Docker image for windows"
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
else ifeq ($(arch1),s390x)
arch2=s390x
else ifeq ($(arch1),ppc64le)
arch2=ppc64le
else
$(error unsupported ARCH: $(arch1))
endif

ignore_suites := $(IGNORE_SUITES)

############################################################################
# Docker TLS detection for buildx
############################################################################
dockertls=
ifeq ($(DOCKER_TLS_VERIFY), 1)
dockertls=spire-buildx-tls
endif

############################################################################
# Vars
############################################################################

PLATFORMS ?= linux/amd64,linux/arm64

binaries := spire-server spire-agent oidc-discovery-provider

build_dir := $(DIR)/.build/$(os1)-$(arch1)

go_version := $(shell cat .go-version)
go_dir := $(build_dir)/go/$(go_version)

ifeq ($(os1),windows)
	go_bin_dir = $(go_dir)/go/bin
	go_url = https://go.dev/dl/go$(go_version).$(os1)-$(arch2).zip
	exe=".exe"
else
	go_bin_dir = $(go_dir)/bin
	go_url = https://go.dev/dl/go$(go_version).$(os1)-$(arch2).tar.gz
	exe=
endif

go_path := PATH="$(go_bin_dir):$(PATH)"

golangci_lint_version := $(shell awk '/golangci-lint/{print $$2}' .spire-tool-versions)
golangci_lint_dir = $(build_dir)/golangci_lint/$(golangci_lint_version)
golangci_lint_cache = $(golangci_lint_dir)/cache

markdown_lint_version := $(shell awk '/markdown_lint/{print $$2}' .spire-tool-versions)
markdown_lint_image = ghcr.io/igorshubovych/markdownlint-cli:$(markdown_lint_version)

protoc_version := $(shell awk '/protoc/{print $$2}' .spire-tool-versions)
ifeq ($(os1),windows)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-win64.zip
else ifeq ($(arch2),arm64)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-aarch_64.zip
else ifeq ($(arch2),s390x)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-s390_64.zip
else ifeq ($(arch2),ppc64le)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-ppcle_64.zip
else
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-$(arch1).zip
endif
protoc_dir = $(build_dir)/protoc/$(protoc_version)
protoc_bin = $(protoc_dir)/bin/protoc

protoc_gen_go_version := $(shell grep google.golang.org/protobuf go.mod | awk '{print $$2}')
protoc_gen_go_base_dir := $(build_dir)/protoc-gen-go
protoc_gen_go_dir := $(protoc_gen_go_base_dir)/$(protoc_gen_go_version)-go$(go_version)
protoc_gen_go_bin := $(protoc_gen_go_dir)/protoc-gen-go

protoc_gen_go_grpc_version := v1.3.0
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
go_test_flags :=
ifeq ($(NIGHTLY),)
	# Cap unit-test timout to 90s unless we're running nightlies.
	go_test_flags += -timeout=90s
endif

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

#############################################################################
# Build Targets
#############################################################################

.PHONY: build
build: tidy $(addprefix bin/,$(binaries))

go_build := $(go_path) go build $(go_flags) -ldflags '$(go_ldflags)' -o

bin/%: cmd/% FORCE | go-check
	@echo Building $@…
	$(E)$(go_build) $@$(exe) ./$<

bin/%: support/% FORCE | go-check
	@echo Building $@…
	$(E)$(go_build) $@$(exe) ./$<

#############################################################################
# Build static binaries for docker images
#############################################################################

.PHONY: build-static
# The build-static is intended to statically link to musl libc.
# There are possibilities of unexpected errors when statically link to GLIBC.
# https://7thzero.com/blog/golang-w-sqlite3-docker-scratch-image
build-static: tidy $(addprefix bin/static/,$(binaries))

go_build_static := $(go_path) go build $(go_flags) -ldflags '$(go_ldflags) -linkmode external -extldflags "-static"' -o

bin/static/%: cmd/% FORCE | go-check
	@echo Building $@…
	$(E)$(go_build_static) $@$(exe) ./$<

bin/static/%: support/% FORCE | go-check
	$(E)$(go_build_static) $@$(exe) ./$<

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

integration:
ifeq ($(os1), windows)
	$(error Integration tests are not supported on windows)
else
	$(E)$(go_path) IGNORE_SUITES='$(ignore_suites)' ./test/integration/test.sh $(SUITES)
endif

integration-windows:
	$(E)$(go_path) IGNORE_SUITES='$(ignore_suites)' ./test/integration/test-windows.sh $(SUITES)

#############################################################################
# Docker Images
#############################################################################

.PHONY: spire-buildx-tls
spire-buildx-tls:
	$(E)docker context rm -f "$(dockertls)" > /dev/null
	$(E)docker context create $(dockertls) --description "$(dockertls)" --docker "host=$(DOCKER_HOST),ca=$(DOCKER_CERT_PATH)/ca.pem,cert=$(DOCKER_CERT_PATH)/cert.pem,key=$(DOCKER_CERT_PATH)/key.pem" > /dev/null

.PHONY: container-builder
container-builder: $(dockertls)
	$(E)docker buildx create $(dockertls) --platform $(PLATFORMS) --name container-builder --node container-builder0 --use

define image_rule
.PHONY: $1
$1: $3 container-builder
	@echo Building docker image $2 $(PLATFORM)…
	$(E)docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg goversion=$(go_version) \
		--build-arg TAG=$(TAG) \
		--target $2 \
		-o type=oci,dest=$2-image.tar \
		-f $3 \
		.

endef

$(eval $(call image_rule,spire-server-image,spire-server,Dockerfile))
$(eval $(call image_rule,spire-agent-image,spire-agent,Dockerfile))
$(eval $(call image_rule,oidc-discovery-provider-image,oidc-discovery-provider,Dockerfile))

.PHONY: images-no-load
images-no-load: $(addsuffix -image,$(binaries))

.PHONY: images
images: images-no-load
	.github/workflows/scripts/load-oci-archives.sh

.PHONY: load-images
load-images:
	.github/workflows/scripts/load-oci-archives.sh

#############################################################################
# Windows Docker Images
#############################################################################
define windows_image_rule
.PHONY: $1
$1: $3
	@echo Building docker image $2…
	$(E)docker build \
		--build-arg goversion=$(go_version) \
		--target $2 \
		-t $2 -t $2:latest-local \
		-f $3 \
		.

endef

.PHONY: images-windows
images-windows: $(addsuffix -windows-image,$(binaries))

$(eval $(call windows_image_rule,spire-server-windows-image,spire-server-windows,Dockerfile.windows))
$(eval $(call windows_image_rule,spire-agent-windows-image,spire-agent-windows,Dockerfile.windows))
$(eval $(call windows_image_rule,oidc-discovery-provider-windows-image,oidc-discovery-provider-windows,Dockerfile.windows))

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

lint: lint-code lint-md

lint-code: | go-check
	$(E)mkdir -p $(golangci_lint_cache)
	$(E)$(go_path) GOLANGCI_LINT_CACHE="$(golangci_lint_cache)" \
		go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(golangci_lint_version) \
		run --max-issues-per-linter=0 --max-same-issues=0 ./...

lint-md:
	$(E)docker run --rm -v "$(DIR):/workdir" $(markdown_lint_image) "**/*.md"

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

install-toolchain: install-protoc install-protoc-gen-go | go-check

install-protoc: $(protoc_bin)

$(protoc_bin):
	@echo "Installing protoc $(protoc_version)..."
	$(E)rm -rf $(dir $(protoc_dir))
	$(E)mkdir -p $(protoc_dir)
	$(E)curl -sSfL $(protoc_url) -o $(build_dir)/tmp.zip; unzip -q -d $(protoc_dir) $(build_dir)/tmp.zip; rm $(build_dir)/tmp.zip

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
