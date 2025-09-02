.PHONY: test build

# This can be changed by exporting an env variable
XGO_TARGETS ?= linux/amd64,windows/amd64,darwin/amd64

GOBIN = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))build/bin
PROJECT_NAME=keycard-cli
BIN_NAME=keycard

# Get version from git tags, fallback to git describe if no tags
VERSION = $(git describe --tags --exact-match 2>/dev/null || git describe --tags --always --dirty)

export GITHUB_USER ?= status-im
export GITHUB_REPO ?= $(PROJECT_NAME)

export IMAGE_TAG   ?= xgo-1.18.1
export IMAGE_NAME  ?= statusteam/keycard-cli-ci:$(IMAGE_TAG)

export GO_PROJECT_PATH ?= github.com/$(GITHUB_USER)/$(GITHUB_REPO)

deps: install-xgo install-github-release
	go version

install-xgo:
	go install github.com/crazy-max/xgo@v0.23.0

install-github-release:
	go install github.com/aktau/github-release@v0.10.0

build:
	go build -o $(GOBIN)/$(BIN_NAME) -v -ldflags "-X main.version=$(VERSION)" .
	@echo "Compilation done."
	@echo "Run \"./build/bin/$(BIN_NAME)\" to view available commands."

test:
	go test -v ./...

docker-image:
	cd _assets/docker && $(MAKE) push

build-platforms:
	xgo \
		-ldflags="-X main.version=$(VERSION)" \
		-out=$(BIN_NAME) \
		-dest=$(GOBIN) \
		-docker-image=$(IMAGE_NAME) \
		-targets=$(XGO_TARGETS) .

release:
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN is not set. Unable to release to GitHub.)
endif
	# FIXME: this might remove a real release if not careful
	-github-release delete --tag $(VERSION)
	github-release release --tag $(VERSION) --draft
	cd $(GOBIN); \
	for FILE in $$(ls); do \
		github-release upload \
			--tag $(VERSION) \
			--file $${FILE} \
			--name $${FILE} \
			--replace; \
	done

clean:
	rm -f $(GOBIN)/*
