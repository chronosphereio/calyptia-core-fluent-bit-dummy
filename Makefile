GORELEASER_IMAGE			?= ghcr.io/chronosphereio/calyptia-core-fluent-bit-template/goreleaser-cross:latest
GORELEASER_CONFIG			:= ./.goreleaser.build.yml
GORELEASER_DEBUG			:= false
GORELEASER_SNAPSHOT         ?= false
PACKAGE_NAME				:= github.com/chronosphereio/calyptia-core-fluent-bit-dummy
PACKAGE_BINARY_NAME			:= calyptia-core-fluent-bit-dummy.so
DOCKER_ARCHS				?= amd64 arm64
BUILD_DOCKER_ARCHS 			= $(addprefix build-,$(DOCKER_ARCHS))
BUILD_DOCKER_IMAGE_ARCHS	= $(addprefix build-image-,$(DOCKER_ARCHS))

GORELEASER_EXTRA_FLAGS =
ifeq ($(GORELEASER_SNAPSHOT), true)
	GORELEASER_EXTRA_FLAGS += --snapshot
endif

.PHONY: build $(BUILD_DOCKER_ARCHS)
build: $(BUILD_DOCKER_ARCHS)
$(BUILD_DOCKER_ARCHS): build-%:
	mkdir -p build/$*
	docker run \
		--rm \
		--platform=linux/$* \
		-v `pwd`:/go/src/$(PACKAGE_NAME) \
		-v /etc/passwd:/etc/passwd:ro --user $(shell id -u):$(shell id -g) \
		-w /go/src/$(PACKAGE_NAME) \
		-e HOME=/go/src/$(PACKAGE_NAME) \
		$(GORELEASER_IMAGE) \
		-f "$(GORELEASER_CONFIG)" \
		--debug=$(GORELEASER_DEBUG) build \
		--output=./build/$*/$(PACKAGE_BINARY_NAME) \
		--id=linux-$* \
		--single-target \
		--clean \
		--skip=validate \
		$(GORELEASER_EXTRA_FLAGS)
