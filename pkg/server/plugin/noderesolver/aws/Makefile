utils = github.com/goreleaser/goreleaser \
		github.com/Masterminds/glide

build:
	go build -i

utils: $(utils)

$(utils): noop
	go get $@

vendor: glide.yaml glide.lock
	glide --home .cache install

test:
	go test -race $$(glide novendor)

release:
	goreleaser || true

clean:
	go clean $$(glide novendor)

noop:

.PHONY: all build vendor utils test clean
