GORELEASER_IMAGE			?= ghcr.io/calyptia/lts-advanced-plugin-template/goreleaser-cross
GORELEASER_CONFIG			:= ./.goreleaser.build.yml
GORELEASER_DOCKERFILE		:= ./Dockerfile.goreleaser
GORELEASER_DEBUG			:= false
GORELEASER_SNAPSHOT         ?= false
PACKAGE_NAME				:= github.com/calyptia/lts-advanced-plugin-dummy
PACKAGE_BINARY_NAME			:= lts-advanced-plugin-dummy.so
DOCKER_ARCHS				?= amd64 arm64
BUILD_DOCKER_ARCHS 			= $(addprefix build-,$(DOCKER_ARCHS))
BUILD_DOCKER_IMAGE_ARCHS	= $(addprefix build-image-,$(DOCKER_ARCHS))

GORELEASER_EXTRA_FLAGS =
ifeq ($(GORELEASER_SNAPSHOT), true)
	GORELEASER_EXTRA_FLAGS += --snapshot
endif

.PHONY: build-image $(BUILD_DOCKER_IMAGE_ARCHS)
build-image: $(BUILD_DOCKER_IMAGE_ARCHS)
$(BUILD_DOCKER_IMAGE_ARCHS): build-image-%:
	docker buildx \
		build \
		--platform=linux/$* -f $(GORELEASER_DOCKERFILE) -t $(GORELEASER_IMAGE)-$* --load .

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
		--skip-validate \
		$(GORELEASER_EXTRA_FLAGS)
