.PHONY: test build dist

# This can be changed by exporting an env variable
XGO_TARGETS ?= linux/amd64,windows/amd64,darwin/amd64

GOBIN = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))build/bin
PROJECT_NAME=keycard-cli
BIN_NAME=keycard

VERSION = $(shell cat VERSION)

export GITHUB_USER ?= keycard-tech
export GITHUB_REPO ?= $(PROJECT_NAME)

export IMAGE_TAG   ?= xgo-1.18.1
export IMAGE_NAME  ?= keycard-tech/keycard-cli-ci:$(IMAGE_TAG)

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

# Release binaries for all platforms are produced by .github/workflows/release.yml
# (push a v* tag, or run it manually from the Actions tab). `dist` builds a single
# artifact with the same naming convention, for the host platform by default:
#
#	make dist GOOS_TARGET=linux GOARCH_TARGET=arm64
#
# Only windows targets can be cross-compiled here (scard's Windows backend is
# pure Go, so CGO is switched off for them); Linux and macOS need cgo and are
# therefore built natively by the workflow.
DIST_DIR ?= $(dir $(realpath $(firstword $(MAKEFILE_LIST))))dist
GOOS_TARGET ?= $(shell go env GOOS)
GOARCH_TARGET ?= $(shell go env GOARCH)

dist:
	@mkdir -p $(DIST_DIR)
	@name="$(BIN_NAME)-$(GOOS_TARGET)-$(GOARCH_TARGET)"; cgo=1; \
	case "$(GOOS_TARGET)" in \
		windows) name="$$name.exe"; cgo=0 ;; \
		linux) pkg-config --exists libpcsclite \
			|| { echo "missing libpcsclite development headers (install libpcsclite-dev)"; exit 1; } ;; \
	esac; \
	echo "building $$name (cgo=$$cgo)"; \
	CGO_ENABLED=$$cgo GOOS=$(GOOS_TARGET) GOARCH=$(GOARCH_TARGET) \
		go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)" \
			-o "$(DIST_DIR)/$$name" .; \
	cd "$(DIST_DIR)" && files=(); for f in *; do \
		[ "$$f" = SHA256SUMS ] || files+=("$$f"); \
	done; sha256sum -- "$${files[@]}" > SHA256SUMS
	@echo "artifacts in $(DIST_DIR):" && ls -1 $(DIST_DIR)

docker-image:
	cd _assets/docker && $(MAKE) push

# Legacy: xgo cross-compilation is superseded by .github/workflows/release.yml,
# which builds every platform natively. Kept for reference only.
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
