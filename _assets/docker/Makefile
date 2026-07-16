GIT_COMMIT = $(shell git rev-parse --short HEAD)
GIT_ROOT = $(shell git rev-parse --show-toplevel)

GO_VERSION ?= 1.18.1
IMAGE_TAG  ?= xgo-$(GO_VERSION)
IMAGE_NAME ?= keycard-tech/keycard-cli-ci:$(IMAGE_TAG)

build:
	docker build \
		--build-arg  "GO_VERSION=$(GO_VERSION)" \
		--label "commit=$(GIT_COMMIT)" \
		-t $(IMAGE_NAME) .

push: build
	docker push $(IMAGE_NAME)

clean:
	docker rmi -f $(IMAGE_NAME)
